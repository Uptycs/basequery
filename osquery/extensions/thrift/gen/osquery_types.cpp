/**
 * Autogenerated by Thrift Compiler (0.13.0)
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */
#include "osquery_types.h"

#include <algorithm>
#include <ostream>

#include <thrift/TToString.h>

namespace osquery {
namespace extensions {

int _kExtensionCodeValues[] = {ExtensionCode::EXT_SUCCESS,
                               ExtensionCode::EXT_FAILED,
                               ExtensionCode::EXT_FATAL};
const char* _kExtensionCodeNames[] = {"EXT_SUCCESS", "EXT_FAILED", "EXT_FATAL"};
const std::map<int, const char*> _ExtensionCode_VALUES_TO_NAMES(
    ::apache::thrift::TEnumIterator(3,
                                    _kExtensionCodeValues,
                                    _kExtensionCodeNames),
    ::apache::thrift::TEnumIterator(-1, NULL, NULL));

std::ostream& operator<<(std::ostream& out, const ExtensionCode::type& val) {
  std::map<int, const char*>::const_iterator it =
      _ExtensionCode_VALUES_TO_NAMES.find(val);
  if (it != _ExtensionCode_VALUES_TO_NAMES.end()) {
    out << it->second;
  } else {
    out << static_cast<int>(val);
  }
  return out;
}

std::string to_string(const ExtensionCode::type& val) {
  std::map<int, const char*>::const_iterator it =
      _ExtensionCode_VALUES_TO_NAMES.find(val);
  if (it != _ExtensionCode_VALUES_TO_NAMES.end()) {
    return std::string(it->second);
  } else {
    return std::to_string(static_cast<int>(val));
  }
}

InternalOptionInfo::~InternalOptionInfo() noexcept {}

void InternalOptionInfo::__set_value(const std::string& val) {
  this->value = val;
}

void InternalOptionInfo::__set_default_value(const std::string& val) {
  this->default_value = val;
}

void InternalOptionInfo::__set_type(const std::string& val) {
  this->type = val;
}
std::ostream& operator<<(std::ostream& out, const InternalOptionInfo& obj) {
  obj.printTo(out);
  return out;
}

uint32_t InternalOptionInfo::read(
    ::apache::thrift::protocol::TProtocol* iprot) {
  ::apache::thrift::protocol::TInputRecursionTracker tracker(*iprot);
  uint32_t xfer = 0;
  std::string fname;
  ::apache::thrift::protocol::TType ftype;
  int16_t fid;

  xfer += iprot->readStructBegin(fname);

  using ::apache::thrift::protocol::TProtocolException;

  while (true) {
    xfer += iprot->readFieldBegin(fname, ftype, fid);
    if (ftype == ::apache::thrift::protocol::T_STOP) {
      break;
    }
    switch (fid) {
    case 1:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->value);
        this->__isset.value = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 2:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->default_value);
        this->__isset.default_value = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 3:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->type);
        this->__isset.type = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    default:
      xfer += iprot->skip(ftype);
      break;
    }
    xfer += iprot->readFieldEnd();
  }

  xfer += iprot->readStructEnd();

  return xfer;
}

uint32_t InternalOptionInfo::write(
    ::apache::thrift::protocol::TProtocol* oprot) const {
  uint32_t xfer = 0;
  ::apache::thrift::protocol::TOutputRecursionTracker tracker(*oprot);
  xfer += oprot->writeStructBegin("InternalOptionInfo");

  xfer +=
      oprot->writeFieldBegin("value", ::apache::thrift::protocol::T_STRING, 1);
  xfer += oprot->writeString(this->value);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin(
      "default_value", ::apache::thrift::protocol::T_STRING, 2);
  xfer += oprot->writeString(this->default_value);
  xfer += oprot->writeFieldEnd();

  xfer +=
      oprot->writeFieldBegin("type", ::apache::thrift::protocol::T_STRING, 3);
  xfer += oprot->writeString(this->type);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldStop();
  xfer += oprot->writeStructEnd();
  return xfer;
}

void swap(InternalOptionInfo& a, InternalOptionInfo& b) {
  using ::std::swap;
  swap(a.value, b.value);
  swap(a.default_value, b.default_value);
  swap(a.type, b.type);
  swap(a.__isset, b.__isset);
}

InternalOptionInfo::InternalOptionInfo(const InternalOptionInfo& other0) {
  value = other0.value;
  default_value = other0.default_value;
  type = other0.type;
  __isset = other0.__isset;
}
InternalOptionInfo::InternalOptionInfo(InternalOptionInfo&& other1) {
  value = std::move(other1.value);
  default_value = std::move(other1.default_value);
  type = std::move(other1.type);
  __isset = std::move(other1.__isset);
}
InternalOptionInfo& InternalOptionInfo::operator=(
    const InternalOptionInfo& other2) {
  value = other2.value;
  default_value = other2.default_value;
  type = other2.type;
  __isset = other2.__isset;
  return *this;
}
InternalOptionInfo& InternalOptionInfo::operator=(InternalOptionInfo&& other3) {
  value = std::move(other3.value);
  default_value = std::move(other3.default_value);
  type = std::move(other3.type);
  __isset = std::move(other3.__isset);
  return *this;
}
void InternalOptionInfo::printTo(std::ostream& out) const {
  using ::apache::thrift::to_string;
  out << "InternalOptionInfo(";
  out << "value=" << to_string(value);
  out << ", "
      << "default_value=" << to_string(default_value);
  out << ", "
      << "type=" << to_string(type);
  out << ")";
}

InternalExtensionInfo::~InternalExtensionInfo() noexcept {}

void InternalExtensionInfo::__set_name(const std::string& val) {
  this->name = val;
}

void InternalExtensionInfo::__set_version(const std::string& val) {
  this->version = val;
}

void InternalExtensionInfo::__set_sdk_version(const std::string& val) {
  this->sdk_version = val;
}

void InternalExtensionInfo::__set_min_sdk_version(const std::string& val) {
  this->min_sdk_version = val;
}
std::ostream& operator<<(std::ostream& out, const InternalExtensionInfo& obj) {
  obj.printTo(out);
  return out;
}

uint32_t InternalExtensionInfo::read(
    ::apache::thrift::protocol::TProtocol* iprot) {
  ::apache::thrift::protocol::TInputRecursionTracker tracker(*iprot);
  uint32_t xfer = 0;
  std::string fname;
  ::apache::thrift::protocol::TType ftype;
  int16_t fid;

  xfer += iprot->readStructBegin(fname);

  using ::apache::thrift::protocol::TProtocolException;

  while (true) {
    xfer += iprot->readFieldBegin(fname, ftype, fid);
    if (ftype == ::apache::thrift::protocol::T_STOP) {
      break;
    }
    switch (fid) {
    case 1:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->name);
        this->__isset.name = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 2:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->version);
        this->__isset.version = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 3:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->sdk_version);
        this->__isset.sdk_version = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 4:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->min_sdk_version);
        this->__isset.min_sdk_version = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    default:
      xfer += iprot->skip(ftype);
      break;
    }
    xfer += iprot->readFieldEnd();
  }

  xfer += iprot->readStructEnd();

  return xfer;
}

uint32_t InternalExtensionInfo::write(
    ::apache::thrift::protocol::TProtocol* oprot) const {
  uint32_t xfer = 0;
  ::apache::thrift::protocol::TOutputRecursionTracker tracker(*oprot);
  xfer += oprot->writeStructBegin("InternalExtensionInfo");

  xfer +=
      oprot->writeFieldBegin("name", ::apache::thrift::protocol::T_STRING, 1);
  xfer += oprot->writeString(this->name);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin(
      "version", ::apache::thrift::protocol::T_STRING, 2);
  xfer += oprot->writeString(this->version);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin(
      "sdk_version", ::apache::thrift::protocol::T_STRING, 3);
  xfer += oprot->writeString(this->sdk_version);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin(
      "min_sdk_version", ::apache::thrift::protocol::T_STRING, 4);
  xfer += oprot->writeString(this->min_sdk_version);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldStop();
  xfer += oprot->writeStructEnd();
  return xfer;
}

void swap(InternalExtensionInfo& a, InternalExtensionInfo& b) {
  using ::std::swap;
  swap(a.name, b.name);
  swap(a.version, b.version);
  swap(a.sdk_version, b.sdk_version);
  swap(a.min_sdk_version, b.min_sdk_version);
  swap(a.__isset, b.__isset);
}

InternalExtensionInfo::InternalExtensionInfo(
    const InternalExtensionInfo& other4) {
  name = other4.name;
  version = other4.version;
  sdk_version = other4.sdk_version;
  min_sdk_version = other4.min_sdk_version;
  __isset = other4.__isset;
}
InternalExtensionInfo::InternalExtensionInfo(InternalExtensionInfo&& other5) {
  name = std::move(other5.name);
  version = std::move(other5.version);
  sdk_version = std::move(other5.sdk_version);
  min_sdk_version = std::move(other5.min_sdk_version);
  __isset = std::move(other5.__isset);
}
InternalExtensionInfo& InternalExtensionInfo::operator=(
    const InternalExtensionInfo& other6) {
  name = other6.name;
  version = other6.version;
  sdk_version = other6.sdk_version;
  min_sdk_version = other6.min_sdk_version;
  __isset = other6.__isset;
  return *this;
}
InternalExtensionInfo& InternalExtensionInfo::operator=(
    InternalExtensionInfo&& other7) {
  name = std::move(other7.name);
  version = std::move(other7.version);
  sdk_version = std::move(other7.sdk_version);
  min_sdk_version = std::move(other7.min_sdk_version);
  __isset = std::move(other7.__isset);
  return *this;
}
void InternalExtensionInfo::printTo(std::ostream& out) const {
  using ::apache::thrift::to_string;
  out << "InternalExtensionInfo(";
  out << "name=" << to_string(name);
  out << ", "
      << "version=" << to_string(version);
  out << ", "
      << "sdk_version=" << to_string(sdk_version);
  out << ", "
      << "min_sdk_version=" << to_string(min_sdk_version);
  out << ")";
}

ExtensionStatus::~ExtensionStatus() noexcept {}

void ExtensionStatus::__set_code(const int32_t val) {
  this->code = val;
}

void ExtensionStatus::__set_message(const std::string& val) {
  this->message = val;
}

void ExtensionStatus::__set_uuid(const ExtensionRouteUUID val) {
  this->uuid = val;
}
std::ostream& operator<<(std::ostream& out, const ExtensionStatus& obj) {
  obj.printTo(out);
  return out;
}

uint32_t ExtensionStatus::read(::apache::thrift::protocol::TProtocol* iprot) {
  ::apache::thrift::protocol::TInputRecursionTracker tracker(*iprot);
  uint32_t xfer = 0;
  std::string fname;
  ::apache::thrift::protocol::TType ftype;
  int16_t fid;

  xfer += iprot->readStructBegin(fname);

  using ::apache::thrift::protocol::TProtocolException;

  while (true) {
    xfer += iprot->readFieldBegin(fname, ftype, fid);
    if (ftype == ::apache::thrift::protocol::T_STOP) {
      break;
    }
    switch (fid) {
    case 1:
      if (ftype == ::apache::thrift::protocol::T_I32) {
        xfer += iprot->readI32(this->code);
        this->__isset.code = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 2:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->message);
        this->__isset.message = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 3:
      if (ftype == ::apache::thrift::protocol::T_I64) {
        xfer += iprot->readI64(this->uuid);
        this->__isset.uuid = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    default:
      xfer += iprot->skip(ftype);
      break;
    }
    xfer += iprot->readFieldEnd();
  }

  xfer += iprot->readStructEnd();

  return xfer;
}

uint32_t ExtensionStatus::write(
    ::apache::thrift::protocol::TProtocol* oprot) const {
  uint32_t xfer = 0;
  ::apache::thrift::protocol::TOutputRecursionTracker tracker(*oprot);
  xfer += oprot->writeStructBegin("ExtensionStatus");

  xfer += oprot->writeFieldBegin("code", ::apache::thrift::protocol::T_I32, 1);
  xfer += oprot->writeI32(this->code);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin(
      "message", ::apache::thrift::protocol::T_STRING, 2);
  xfer += oprot->writeString(this->message);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin("uuid", ::apache::thrift::protocol::T_I64, 3);
  xfer += oprot->writeI64(this->uuid);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldStop();
  xfer += oprot->writeStructEnd();
  return xfer;
}

void swap(ExtensionStatus& a, ExtensionStatus& b) {
  using ::std::swap;
  swap(a.code, b.code);
  swap(a.message, b.message);
  swap(a.uuid, b.uuid);
  swap(a.__isset, b.__isset);
}

ExtensionStatus::ExtensionStatus(const ExtensionStatus& other8) {
  code = other8.code;
  message = other8.message;
  uuid = other8.uuid;
  __isset = other8.__isset;
}
ExtensionStatus::ExtensionStatus(ExtensionStatus&& other9) {
  code = std::move(other9.code);
  message = std::move(other9.message);
  uuid = std::move(other9.uuid);
  __isset = std::move(other9.__isset);
}
ExtensionStatus& ExtensionStatus::operator=(const ExtensionStatus& other10) {
  code = other10.code;
  message = other10.message;
  uuid = other10.uuid;
  __isset = other10.__isset;
  return *this;
}
ExtensionStatus& ExtensionStatus::operator=(ExtensionStatus&& other11) {
  code = std::move(other11.code);
  message = std::move(other11.message);
  uuid = std::move(other11.uuid);
  __isset = std::move(other11.__isset);
  return *this;
}
void ExtensionStatus::printTo(std::ostream& out) const {
  using ::apache::thrift::to_string;
  out << "ExtensionStatus(";
  out << "code=" << to_string(code);
  out << ", "
      << "message=" << to_string(message);
  out << ", "
      << "uuid=" << to_string(uuid);
  out << ")";
}

ExtensionResponse::~ExtensionResponse() noexcept {}

void ExtensionResponse::__set_status(const ExtensionStatus& val) {
  this->status = val;
}

void ExtensionResponse::__set_response(const ExtensionPluginResponse& val) {
  this->response = val;
}
std::ostream& operator<<(std::ostream& out, const ExtensionResponse& obj) {
  obj.printTo(out);
  return out;
}

uint32_t ExtensionResponse::read(::apache::thrift::protocol::TProtocol* iprot) {
  ::apache::thrift::protocol::TInputRecursionTracker tracker(*iprot);
  uint32_t xfer = 0;
  std::string fname;
  ::apache::thrift::protocol::TType ftype;
  int16_t fid;

  xfer += iprot->readStructBegin(fname);

  using ::apache::thrift::protocol::TProtocolException;

  while (true) {
    xfer += iprot->readFieldBegin(fname, ftype, fid);
    if (ftype == ::apache::thrift::protocol::T_STOP) {
      break;
    }
    switch (fid) {
    case 1:
      if (ftype == ::apache::thrift::protocol::T_STRUCT) {
        xfer += this->status.read(iprot);
        this->__isset.status = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 2:
      if (ftype == ::apache::thrift::protocol::T_LIST) {
        {
          this->response.clear();
          uint32_t _size12;
          ::apache::thrift::protocol::TType _etype15;
          xfer += iprot->readListBegin(_etype15, _size12);
          this->response.resize(_size12);
          uint32_t _i16;
          for (_i16 = 0; _i16 < _size12; ++_i16) {
            {
              this->response[_i16].clear();
              uint32_t _size17;
              ::apache::thrift::protocol::TType _ktype18;
              ::apache::thrift::protocol::TType _vtype19;
              xfer += iprot->readMapBegin(_ktype18, _vtype19, _size17);
              uint32_t _i21;
              for (_i21 = 0; _i21 < _size17; ++_i21) {
                std::string _key22;
                xfer += iprot->readString(_key22);
                std::string& _val23 = this->response[_i16][_key22];
                xfer += iprot->readString(_val23);
              }
              xfer += iprot->readMapEnd();
            }
          }
          xfer += iprot->readListEnd();
        }
        this->__isset.response = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    default:
      xfer += iprot->skip(ftype);
      break;
    }
    xfer += iprot->readFieldEnd();
  }

  xfer += iprot->readStructEnd();

  return xfer;
}

uint32_t ExtensionResponse::write(
    ::apache::thrift::protocol::TProtocol* oprot) const {
  uint32_t xfer = 0;
  ::apache::thrift::protocol::TOutputRecursionTracker tracker(*oprot);
  xfer += oprot->writeStructBegin("ExtensionResponse");

  xfer +=
      oprot->writeFieldBegin("status", ::apache::thrift::protocol::T_STRUCT, 1);
  xfer += this->status.write(oprot);
  xfer += oprot->writeFieldEnd();

  xfer +=
      oprot->writeFieldBegin("response", ::apache::thrift::protocol::T_LIST, 2);
  {
    xfer += oprot->writeListBegin(::apache::thrift::protocol::T_MAP,
                                  static_cast<uint32_t>(this->response.size()));
    std::vector<std::map<std::string, std::string>>::const_iterator _iter24;
    for (_iter24 = this->response.begin(); _iter24 != this->response.end();
         ++_iter24) {
      {
        xfer += oprot->writeMapBegin(::apache::thrift::protocol::T_STRING,
                                     ::apache::thrift::protocol::T_STRING,
                                     static_cast<uint32_t>((*_iter24).size()));
        std::map<std::string, std::string>::const_iterator _iter25;
        for (_iter25 = (*_iter24).begin(); _iter25 != (*_iter24).end();
             ++_iter25) {
          xfer += oprot->writeString(_iter25->first);
          xfer += oprot->writeString(_iter25->second);
        }
        xfer += oprot->writeMapEnd();
      }
    }
    xfer += oprot->writeListEnd();
  }
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldStop();
  xfer += oprot->writeStructEnd();
  return xfer;
}

void swap(ExtensionResponse& a, ExtensionResponse& b) {
  using ::std::swap;
  swap(a.status, b.status);
  swap(a.response, b.response);
  swap(a.__isset, b.__isset);
}

ExtensionResponse::ExtensionResponse(const ExtensionResponse& other26) {
  status = other26.status;
  response = other26.response;
  __isset = other26.__isset;
}
ExtensionResponse::ExtensionResponse(ExtensionResponse&& other27) {
  status = std::move(other27.status);
  response = std::move(other27.response);
  __isset = std::move(other27.__isset);
}
ExtensionResponse& ExtensionResponse::operator=(
    const ExtensionResponse& other28) {
  status = other28.status;
  response = other28.response;
  __isset = other28.__isset;
  return *this;
}
ExtensionResponse& ExtensionResponse::operator=(ExtensionResponse&& other29) {
  status = std::move(other29.status);
  response = std::move(other29.response);
  __isset = std::move(other29.__isset);
  return *this;
}
void ExtensionResponse::printTo(std::ostream& out) const {
  using ::apache::thrift::to_string;
  out << "ExtensionResponse(";
  out << "status=" << to_string(status);
  out << ", "
      << "response=" << to_string(response);
  out << ")";
}

ExtensionException::~ExtensionException() noexcept {}

void ExtensionException::__set_code(const int32_t val) {
  this->code = val;
}

void ExtensionException::__set_message(const std::string& val) {
  this->message = val;
}

void ExtensionException::__set_uuid(const ExtensionRouteUUID val) {
  this->uuid = val;
}
std::ostream& operator<<(std::ostream& out, const ExtensionException& obj) {
  obj.printTo(out);
  return out;
}

uint32_t ExtensionException::read(
    ::apache::thrift::protocol::TProtocol* iprot) {
  ::apache::thrift::protocol::TInputRecursionTracker tracker(*iprot);
  uint32_t xfer = 0;
  std::string fname;
  ::apache::thrift::protocol::TType ftype;
  int16_t fid;

  xfer += iprot->readStructBegin(fname);

  using ::apache::thrift::protocol::TProtocolException;

  while (true) {
    xfer += iprot->readFieldBegin(fname, ftype, fid);
    if (ftype == ::apache::thrift::protocol::T_STOP) {
      break;
    }
    switch (fid) {
    case 1:
      if (ftype == ::apache::thrift::protocol::T_I32) {
        xfer += iprot->readI32(this->code);
        this->__isset.code = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 2:
      if (ftype == ::apache::thrift::protocol::T_STRING) {
        xfer += iprot->readString(this->message);
        this->__isset.message = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    case 3:
      if (ftype == ::apache::thrift::protocol::T_I64) {
        xfer += iprot->readI64(this->uuid);
        this->__isset.uuid = true;
      } else {
        xfer += iprot->skip(ftype);
      }
      break;
    default:
      xfer += iprot->skip(ftype);
      break;
    }
    xfer += iprot->readFieldEnd();
  }

  xfer += iprot->readStructEnd();

  return xfer;
}

uint32_t ExtensionException::write(
    ::apache::thrift::protocol::TProtocol* oprot) const {
  uint32_t xfer = 0;
  ::apache::thrift::protocol::TOutputRecursionTracker tracker(*oprot);
  xfer += oprot->writeStructBegin("ExtensionException");

  xfer += oprot->writeFieldBegin("code", ::apache::thrift::protocol::T_I32, 1);
  xfer += oprot->writeI32(this->code);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin(
      "message", ::apache::thrift::protocol::T_STRING, 2);
  xfer += oprot->writeString(this->message);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldBegin("uuid", ::apache::thrift::protocol::T_I64, 3);
  xfer += oprot->writeI64(this->uuid);
  xfer += oprot->writeFieldEnd();

  xfer += oprot->writeFieldStop();
  xfer += oprot->writeStructEnd();
  return xfer;
}

void swap(ExtensionException& a, ExtensionException& b) {
  using ::std::swap;
  swap(a.code, b.code);
  swap(a.message, b.message);
  swap(a.uuid, b.uuid);
  swap(a.__isset, b.__isset);
}

ExtensionException::ExtensionException(const ExtensionException& other30)
    : TException() {
  code = other30.code;
  message = other30.message;
  uuid = other30.uuid;
  __isset = other30.__isset;
}
ExtensionException::ExtensionException(ExtensionException&& other31)
    : TException() {
  code = std::move(other31.code);
  message = std::move(other31.message);
  uuid = std::move(other31.uuid);
  __isset = std::move(other31.__isset);
}
ExtensionException& ExtensionException::operator=(
    const ExtensionException& other32) {
  code = other32.code;
  message = other32.message;
  uuid = other32.uuid;
  __isset = other32.__isset;
  return *this;
}
ExtensionException& ExtensionException::operator=(
    ExtensionException&& other33) {
  code = std::move(other33.code);
  message = std::move(other33.message);
  uuid = std::move(other33.uuid);
  __isset = std::move(other33.__isset);
  return *this;
}
void ExtensionException::printTo(std::ostream& out) const {
  using ::apache::thrift::to_string;
  out << "ExtensionException(";
  out << "code=" << to_string(code);
  out << ", "
      << "message=" << to_string(message);
  out << ", "
      << "uuid=" << to_string(uuid);
  out << ")";
}

const char* ExtensionException::what() const noexcept {
  try {
    std::stringstream ss;
    ss << "TException - service has thrown: " << *this;
    this->thriftTExceptionMessageHolder_ = ss.str();
    return this->thriftTExceptionMessageHolder_.c_str();
  } catch (const std::exception&) {
    return "TException - service has thrown: ExtensionException";
  }
}

} // namespace extensions
} // namespace osquery
