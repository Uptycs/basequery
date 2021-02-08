/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <csignal>
#include <ctime>

#include <thread>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/core.h>
#include <osquery/core/flags.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/remote/tests/test_utils.h>
#include <osquery/sql/sql.h>
#include <osquery/tests/test_util.h>
#include <osquery/utils/conversions/join.h>
#include <osquery/utils/json/json.h>
#include <osquery/utils/system/time.h>

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_string(tls_hostname);
DECLARE_string(enroll_tls_endpoint);
DECLARE_string(tls_server_certs);
DECLARE_string(enroll_secret_path);

Status TLSServerRunner::startAndSetScript(const std::string& port,
                                          const std::string& server_cert) {
  auto script = (getTestHelperScriptsDirectory() / "test_http_server.py");
  auto config_dir = getTestConfigDirectory();
  std::vector<std::string> args = {
      script.make_preferred().string(),
      "--tls",
      "--verbose",
      "--test-configs-dir",
      config_dir.make_preferred().string(),
  };

  if (!server_cert.empty()) {
    args.push_back("--cert");
    args.push_back(server_cert);
  }

  args.push_back(port);

  const auto cmd = osquery::join(args, " ");
  server_ = PlatformProcess::launchTestPythonScript(cmd);
  if (server_ == nullptr) {
    return Status::failure("Cannot create test python script: " + cmd);
  }
  return Status::success();
}

bool TLSServerRunner::start(const std::string& server_cert) {
  auto& self = instance();
  if (self.server_ != nullptr) {
    return true;
  }

  self.port_ = "46852";
  auto status = self.startAndSetScript(self.port_, server_cert);
  if (!status.ok()) {
    // This is an unexpected problem, retry without waiting.
    LOG(WARNING) << status.getMessage();
    return false;
  }

  sleepFor(2000);
  return true;
}

void TLSServerRunner::setClientConfig() {
  auto& self = instance();

  self.tls_hostname_ = Flag::getValue("tls_hostname");
  Flag::updateValue("tls_hostname", "localhost:" + port());

  self.enroll_tls_endpoint_ = Flag::getValue("enroll_tls_endpoint");
  Flag::updateValue("enroll_tls_endpoint", "/enroll");

  self.tls_server_certs_ = Flag::getValue("tls_server_certs");
  Flag::updateValue("tls_server_certs",
                    (getTestConfigDirectory() / "test_server_ca.pem")
                        .make_preferred()
                        .string());

  self.enroll_secret_path_ = Flag::getValue("enroll_secret_path");
  Flag::updateValue("enroll_secret_path",
                    (getTestConfigDirectory() / "test_enroll_secret.txt")
                        .make_preferred()
                        .string());
}

void TLSServerRunner::unsetClientConfig() {
  auto& self = instance();
  Flag::updateValue("tls_hostname", self.tls_hostname_);
  Flag::updateValue("enroll_tls_endpoint", self.enroll_tls_endpoint_);
  Flag::updateValue("tls_server_certs", self.tls_server_certs_);
  Flag::updateValue("enroll_secret_path", self.enroll_secret_path_);
}

void TLSServerRunner::stop() {
  auto& self = instance();
  if (self.server_ != nullptr) {
    self.server_->kill();
    self.server_.reset();
  }
}
} // namespace osquery
