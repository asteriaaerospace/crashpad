// Copyright 2015 The Crashpad Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "handler/win/crash_report_exception_handler.h"

#include <type_traits>
#include <utility>

#include "base/strings/utf_string_conversions.h"
#include "client/crash_report_database.h"
#include "client/settings.h"
#include "handler/crash_report_upload_thread.h"
#include "minidump/minidump_file_writer.h"
#include "minidump/minidump_user_extension_stream_data_source.h"
#include "snapshot/win/process_snapshot_win.h"
#include "util/file/file_helper.h"
#include "util/file/file_writer.h"
#include "util/misc/metrics.h"
#include "util/win/registration_protocol_win.h"
#include "util/win/scoped_process_suspend.h"
#include "util/win/termination_codes.h"

namespace crashpad {

namespace {

const wchar_t* ExceptionName(uint32_t code) {
  switch (code) {
    case 0xc0000005: return L"ACCESS_VIOLATION";
    case 0xc0000094: return L"INTEGER_DIVIDE_BY_ZERO";
    case 0xc00000fd: return L"STACK_OVERFLOW";
    case 0xc000001d: return L"ILLEGAL_INSTRUCTION";
    case 0xc0000374: return L"HEAP_CORRUPTION";
    case 0xc0000409: return L"STACK_BUFFER_OVERRUN";
    default: return L"UNKNOWN";
  }
}

void WriteCrashInfoFile(const CrashReportDatabase::Report& report,
                        const ProcessSnapshotWin& process_snapshot) {
  const base::FilePath info_path(report.file_path.RemoveFinalExtension().value() +
                                 L".txt");
  const base::FilePath temporary_path(info_path.value() + L".tmp");
  HANDLE file = CreateFileW(temporary_path.value().c_str(), GENERIC_WRITE, 0,
                            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                            nullptr);
  if (file == INVALID_HANDLE_VALUE) {
    LOG(ERROR) << "Unable to create crash info file, error " << GetLastError();
    return;
  }

  // Make the UTF-16LE encoding explicit for Notepad and PowerShell. The
  // metadata itself is written as wide characters below.
  constexpr wchar_t kUtf16LeByteOrderMark = 0xfeff;
  DWORD written = 0;
  if (!::WriteFile(file, &kUtf16LeByteOrderMark,
                   sizeof(kUtf16LeByteOrderMark), &written, nullptr) ||
      written != sizeof(kUtf16LeByteOrderMark)) {
    LOG(ERROR) << "Unable to write crash info file encoding marker, error "
               << GetLastError();
    CloseHandle(file);
    DeleteFileW(temporary_path.value().c_str());
    return;
  }

  const auto& annotations = process_snapshot.AnnotationsSimpleMap();
  const auto annotation = [&annotations](const char* key) {
    const auto value = annotations.find(key);
    return value == annotations.end() ? std::wstring(L"unknown")
                                      : base::UTF8ToWide(value->second);
  };
  const std::wstring application = annotation("mcs_version");
  const std::wstring build_date = annotation("mcs_build_date");
  const ExceptionSnapshot* exception = process_snapshot.Exception();

  SYSTEMTIME now;
  GetLocalTime(&now);
  wchar_t buffer[4096] = {};
  int length = swprintf_s(
      buffer, sizeof(buffer) / sizeof(buffer[0]),
      L"Crash Analytics Report\r\n"
      L"======================\r\n"
      L"Time (local) : %04u-%02u-%02u %02u:%02u:%02u.%03u\r\n"
      L"Application  : %s\r\n"
      L"Build date   : %s\r\n"
      L"Process ID   : %lu\r\n"
      L"Thread ID    : %llu\r\n"
      L"Exception    : 0x%08X (%s)\r\n"
      L"Fault address: 0x%llX\r\n"
      L"Report ID    : %s\r\n"
      L"Minidump file: %s\r\n"
      L"Crashpad DB  : %s\r\n"
      L"Dump written : yes\r\n"
      L"Symbolize    : Scripts/symbolize_crash.ps1 <this .dmp>\r\n",
      now.wYear, now.wMonth, now.wDay, now.wHour, now.wMinute, now.wSecond,
      now.wMilliseconds, application.c_str(),
      build_date.c_str(),
      static_cast<unsigned long>(process_snapshot.ProcessID()),
      static_cast<unsigned long long>(exception ? exception->ThreadID() : 0),
      exception ? exception->Exception() : 0,
      ExceptionName(exception ? exception->Exception() : 0),
      static_cast<unsigned long long>(exception ? exception->ExceptionAddress() : 0),
      report.uuid.ToWString().c_str(), report.file_path.value().c_str(),
      report.file_path.DirName().DirName().value().c_str());
  if (length > 0) {
    written = 0;
    const DWORD expected = static_cast<DWORD>(length * sizeof(wchar_t));
    if (!::WriteFile(file, buffer, expected, &written, nullptr) ||
        written != expected) {
      LOG(ERROR) << "Unable to write crash info file, error " << GetLastError();
      CloseHandle(file);
      DeleteFileW(temporary_path.value().c_str());
      return;
    }
  }
  CloseHandle(file);
  if (!MoveFileExW(temporary_path.value().c_str(), info_path.value().c_str(),
                   MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    LOG(ERROR) << "Unable to finalize crash info file, error " << GetLastError();
    DeleteFileW(temporary_path.value().c_str());
  }
}

}  // namespace

CrashReportExceptionHandler::CrashReportExceptionHandler(
    CrashReportDatabase* database,
    CrashReportUploadThread* upload_thread,
    const std::map<std::string, std::string>* process_annotations,
    const std::vector<base::FilePath>* attachments,
    const UserStreamDataSources* user_stream_data_sources)
    : database_(database),
      upload_thread_(upload_thread),
      process_annotations_(process_annotations),
      attachments_(attachments),
      user_stream_data_sources_(user_stream_data_sources) {}

CrashReportExceptionHandler::~CrashReportExceptionHandler() {}

void CrashReportExceptionHandler::ExceptionHandlerServerStarted() {}

unsigned int CrashReportExceptionHandler::ExceptionHandlerServerException(
    HANDLE process,
    WinVMAddress exception_information_address,
    WinVMAddress debug_critical_section_address) {
  Metrics::ExceptionEncountered();

  ScopedProcessSuspend suspend(process);

  ProcessSnapshotWin process_snapshot;
  if (!process_snapshot.Initialize(process,
                                   ProcessSuspensionState::kSuspended,
                                   exception_information_address,
                                   debug_critical_section_address)) {
    Metrics::ExceptionCaptureResult(Metrics::CaptureResult::kSnapshotFailed);
    return kTerminationCodeSnapshotFailed;
  }

  // Now that we have the exception information, even if something else fails we
  // can terminate the process with the correct exit code.
  const unsigned int termination_code =
      process_snapshot.Exception()->Exception();
  static_assert(
      std::is_same<std::remove_const<decltype(termination_code)>::type,
                   decltype(process_snapshot.Exception()->Exception())>::value,
      "expected ExceptionCode() and process termination code to match");

  Metrics::ExceptionCode(termination_code);

  CrashpadInfoClientOptions client_options;
  process_snapshot.GetCrashpadOptions(&client_options);
  if (client_options.crashpad_handler_behavior != TriState::kDisabled) {
    UUID client_id;
    Settings* const settings = database_->GetSettings();
    if (settings && settings->GetClientID(&client_id)) {
      process_snapshot.SetClientID(client_id);
    }

    process_snapshot.SetAnnotationsSimpleMap(*process_annotations_);

    std::unique_ptr<CrashReportDatabase::NewReport> new_report;
    CrashReportDatabase::OperationStatus database_status =
        database_->PrepareNewCrashReport(&new_report);
    if (database_status != CrashReportDatabase::kNoError) {
      LOG(ERROR) << "PrepareNewCrashReport failed";
      Metrics::ExceptionCaptureResult(
          Metrics::CaptureResult::kPrepareNewCrashReportFailed);
      return termination_code;
    }

    process_snapshot.SetReportID(new_report->ReportID());

    MinidumpFileWriter minidump;
    minidump.InitializeFromSnapshot(&process_snapshot);
    AddUserExtensionStreams(
        user_stream_data_sources_, &process_snapshot, &minidump);

    if (!minidump.WriteEverything(new_report->Writer())) {
      LOG(ERROR) << "WriteEverything failed";
      Metrics::ExceptionCaptureResult(
          Metrics::CaptureResult::kMinidumpWriteFailed);
      return termination_code;
    }

    for (const auto& attachment : (*attachments_)) {
      FileReader file_reader;
      if (!file_reader.Open(attachment)) {
        LOG(ERROR) << "attachment " << attachment
                   << " couldn't be opened, skipping";
        continue;
      }

      base::FilePath filename = attachment.BaseName();
      FileWriter* file_writer =
          new_report->AddAttachment(base::WideToUTF8(filename.value()));
      if (file_writer == nullptr) {
        LOG(ERROR) << "attachment " << filename
                   << " couldn't be created, skipping";
        continue;
      }

      CopyFileContent(&file_reader, file_writer);
    }

    UUID uuid;
    database_status =
        database_->FinishedWritingCrashReport(std::move(new_report), &uuid);
    if (database_status != CrashReportDatabase::kNoError) {
      LOG(ERROR) << "FinishedWritingCrashReport failed";
      Metrics::ExceptionCaptureResult(
          Metrics::CaptureResult::kFinishedWritingCrashReportFailed);
      return termination_code;
    }

    CrashReportDatabase::Report report;
    if (database_->LookUpCrashReport(uuid, &report) ==
        CrashReportDatabase::kNoError) {
      WriteCrashInfoFile(report, process_snapshot);
    } else {
      LOG(ERROR) << "LookUpCrashReport failed while writing crash info file";
    }

    if (upload_thread_) {
      upload_thread_->ReportPending(uuid);
    }
  }

  Metrics::ExceptionCaptureResult(Metrics::CaptureResult::kSuccess);
  return termination_code;
}

}  // namespace crashpad
