// Copyright 2007-2010 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ========================================================================

#ifndef OMAHA_GOOPDATE_CRASH_H_
#define OMAHA_GOOPDATE_CRASH_H_

#include <windows.h>
#include <dbghelp.h>
#include <atlsecurity.h>
#include <atlstr.h>
#include <map>
#include "base/basictypes.h"
#include "gtest/gtest_prod.h"
#include "omaha/common/const_goopdate.h"
#include "third_party/breakpad/src/client/windows/crash_generation/client_info.h"
#include "third_party/breakpad/src/client/windows/crash_generation/crash_generation_server.h"

namespace omaha {

// TODO(omaha): refactor so this is not a static class.
class CrashReporter {
 public:
  typedef std::map<std::wstring, std::wstring> ParameterMap;

  CrashReporter();

  // Prepares the crash reporter.  Call before making any calls to Report().
  HRESULT Initialize(bool is_machine);

  // Reports a crash by logging it to the Windows event log, saving a copy of
  // the crash, and uploading it. After reporting the crash, the function
  // deletes the crash file. Crashes that have a custom info file are
  // always handled out-of-process and always uploaded if they are product
  // crashes.
  // Crashes that do not specify a custom info file are handled in-process.
  HRESULT Report(const CString& crash_filename,
                 const CString& custom_info_filename);

  // Sets how many reports can be sent until the crash report sender starts
  // rejecting and discarding crashes.
  void SetMaxReportsPerDay(int max_reports_per_day) {
    max_reports_per_day_ = max_reports_per_day;
  }

  // Sets an alternate URL to upload crashes to.
  void SetCrashReportUrl(const TCHAR* crash_report_url) {
    crash_report_url_ = crash_report_url;
  }

 private:
  // Builds a ParameterMap from a custom info file previously generated by
  // GoogleCrashHandler.
  HRESULT ReadCustomInfoFile(const CString& custom_info_filename,
                             ParameterMap* parameters);

  // Builds a ParameterMap from the copy of Google Update currently running.
  void BuildParametersFromGoopdate(ParameterMap* parameters);

  // Sends a crash report. If sent successfully, report_id contains the
  // report id generated by the crash server.
  HRESULT DoSendCrashReport(bool can_upload,
                            bool is_out_of_process,
                            const CString& crash_filename,
                            const ParameterMap& parameters,
                            CString* report_id);

  // Uploads the crash, logs the result of the crash upload, and updates
  // the crash metrics.
  HRESULT UploadCrash(bool is_out_of_process,
                      const CString& crash_filename,
                      const ParameterMap& parameters,
                      CString* report_id);

  // Creates a back up copy of the current crash for future debugging use cases.
  HRESULT SaveLastCrash(const CString& crash_filename,
                        const CString& product_name);

  // Cleans up stale crashes from the crash dir. Curently, crashes older than
  // 1 day are deleted.
  HRESULT CleanStaleCrashes();

  // Logs an entry in the Windows Event Log for the specified source.
  static HRESULT WriteToWindowsEventLog(uint16 type,
                                        uint32 id,
                                        const TCHAR* source,
                                        const TCHAR* description);

  // Reads a key/value pair from a ParameterMap without modifying it.  Returns
  // an empty string if the key isn't found.
  static CString ReadMapValue(const ParameterMap& parameters,
                              const CString& key);

  // Returns the "prod" product name if found in the map or a default,
  // constant string otherwise.
  static CString ReadMapProductName(const ParameterMap& parameters);

  // Returns a string which is appropriate to log in the event log. The
  // string is either the product name or a default value in the case of OOP
  // handling or "Google Update" for Omaha crashes.
  static CString GetProductNameForEventLogging(const ParameterMap& parameters);

  // Updates the crash metrics after uploading the crash.
  static void UpdateCrashUploadMetrics(bool is_out_of_process, HRESULT hr);

  bool is_machine_;
  CString crash_dir_;
  CString checkpoint_file_;
  CString crash_report_url_;
  int max_reports_per_day_;

  static const int kCrashReportAttempts       = 3;
  static const int kCrashReportResendPeriodMs = 1 * 60 * 60 * 1000;  // 1 hour.

  // Default string to report out-of-process crashes with in the case
  // 'prod' information is not available.
  static const TCHAR* const kDefaultProductName;

  friend class CrashReporterTest;

  FRIEND_TEST(CrashReporterTest, CleanStaleCrashes);
  FRIEND_TEST(CrashReporterTest, GetProductName);
  FRIEND_TEST(CrashReporterTest, Report_OmahaCrash);
  FRIEND_TEST(CrashReporterTest, Report_ProductCrash);
  FRIEND_TEST(CrashReporterTest, SaveLastCrash);
  FRIEND_TEST(CrashReporterTest, DISABLED_WriteMinidump);

  DISALLOW_COPY_AND_ASSIGN(CrashReporter);
};

}  // namespace omaha

#endif  // OMAHA_GOOPDATE_CRASH_H_

