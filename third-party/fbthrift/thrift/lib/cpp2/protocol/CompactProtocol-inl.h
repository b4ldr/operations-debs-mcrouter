/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef THRIFT2_PROTOCOL_COMPACTPROTOCOL_TCC_
#define THRIFT2_PROTOCOL_COMPACTPROTOCOL_TCC_ 1

#include <thrift/lib/cpp2/protocol/CompactProtocol.h>

#include <limits>

#include <thrift/lib/cpp/util/VarintUtils.h>

namespace apache {
namespace thrift {

namespace detail {
namespace compact {

enum Types {
  CT_STOP = 0x00,
  CT_BOOLEAN_TRUE = 0x01,
  CT_BOOLEAN_FALSE = 0x02,
  CT_BYTE = 0x03,
  CT_I16 = 0x04,
  CT_I32 = 0x05,
  CT_I64 = 0x06,
  CT_DOUBLE = 0x07,
  CT_BINARY = 0x08,
  CT_LIST = 0x09,
  CT_SET = 0x0A,
  CT_MAP = 0x0B,
  CT_STRUCT = 0x0C,
  CT_FLOAT = 0x0D,
};

const int8_t TTypeToCType[20] = {
    CT_STOP, // T_STOP
    0, // unused
    CT_BOOLEAN_TRUE, // T_BOOL
    CT_BYTE, // T_BYTE
    CT_DOUBLE, // T_DOUBLE
    0, // unused
    CT_I16, // T_I16
    0, // unused
    CT_I32, // T_I32
    0, // unused
    CT_I64, // T_I64
    CT_BINARY, // T_STRING
    CT_STRUCT, // T_STRUCT
    CT_MAP, // T_MAP
    CT_SET, // T_SET
    CT_LIST, // T_LIST
    0, // unused
    0, // unused
    0, // unused
    CT_FLOAT, // T_FLOAT
};

const TType CTypeToTType[14] = {
    TType::T_STOP, // CT_STOP
    TType::T_BOOL, // CT_BOOLEAN_TRUE
    TType::T_BOOL, // CT_BOOLEAN_FASLE
    TType::T_BYTE, // CT_BYTE
    TType::T_I16, // CT_I16
    TType::T_I32, // CT_I32
    TType::T_I64, // CT_I64
    TType::T_DOUBLE, // CT_DOUBLE
    TType::T_STRING, // CT_BINARY
    TType::T_LIST, // CT_LIST
    TType::T_SET, // CT_SET
    TType::T_MAP, // CT_MAP
    TType::T_STRUCT, // CT_STRUCT
    TType::T_FLOAT, // CT_FLOAT
};

} // namespace compact
} // namespace detail

uint32_t CompactProtocolWriter::writeMessageBegin(
    folly::StringPiece name,
    MessageType messageType,
    int32_t seqid) {
  uint32_t wsize = 0;
  wsize += writeByte(detail::compact::PROTOCOL_ID);
  wsize += writeByte(
      detail::compact::COMPACT_PROTOCOL_VERSION |
      ((messageType << detail::compact::TYPE_SHIFT_AMOUNT) &
       detail::compact::TYPE_MASK));
  wsize += apache::thrift::util::writeVarint(out_, seqid);
  wsize += writeString(name);
  return wsize;
}

uint32_t CompactProtocolWriter::writeMessageEnd() {
  return 0;
}

uint32_t CompactProtocolWriter::writeStructBegin(const char* /* name */) {
  lastField_.push(lastFieldId_);
  lastFieldId_ = 0;
  return 0;
}

uint32_t CompactProtocolWriter::writeStructEnd() {
  lastFieldId_ = lastField_.top();
  lastField_.pop();
  return 0;
}

/**
 * The workhorse of writeFieldBegin. It has the option of doing a
 * 'type override' of the type header. This is used specifically in the
 * boolean field case.
 */
uint32_t CompactProtocolWriter::writeFieldBeginInternal(
    const char* /*name*/,
    const TType fieldType,
    const int16_t fieldId,
    int8_t typeOverride) {
  uint32_t wsize = 0;

  // if there's a type override, use that.
  int8_t typeToWrite =
      (typeOverride == -1 ? detail::compact::TTypeToCType[fieldType]
                          : typeOverride);

  // check if we can use delta encoding for the field id
  if (fieldId > lastFieldId_ && fieldId - lastFieldId_ <= 15) {
    // write them together
    wsize += writeByte((fieldId - lastFieldId_) << 4 | typeToWrite);
  } else {
    // write them separate
    wsize += writeByte(typeToWrite);
    wsize += writeI16(fieldId);
  }

  lastFieldId_ = fieldId;
  return wsize;
}

uint32_t CompactProtocolWriter::writeFieldBegin(
    const char* name,
    TType fieldType,
    int16_t fieldId) {
  if (fieldType == TType::T_BOOL) {
    booleanField_.name = name;
    booleanField_.fieldType = fieldType;
    booleanField_.fieldId = fieldId;
  } else {
    return writeFieldBeginInternal(name, fieldType, fieldId, -1);
  }
  return 0;
}

uint32_t CompactProtocolWriter::writeFieldEnd() {
  return 0;
}

uint32_t CompactProtocolWriter::writeFieldStop() {
  return writeByte((int8_t)TType::T_STOP);
}

uint32_t CompactProtocolWriter::writeMapBegin(
    const TType keyType,
    TType valType,
    uint32_t size) {
  uint32_t wsize = 0;

  if (size == 0) {
    wsize += writeByte(0);
  } else {
    wsize += apache::thrift::util::writeVarint(out_, size);
    wsize += writeByte(
        detail::compact::TTypeToCType[keyType] << 4 |
        detail::compact::TTypeToCType[valType]);
  }
  return wsize;
}

uint32_t CompactProtocolWriter::writeMapEnd() {
  return 0;
}

uint32_t CompactProtocolWriter::writeCollectionBegin(
    int8_t elemType,
    int32_t size) {
  uint32_t wsize = 0;
  if (size <= 14) {
    wsize += writeByte(size << 4 | detail::compact::TTypeToCType[elemType]);
  } else {
    wsize += writeByte(0xf0 | detail::compact::TTypeToCType[elemType]);
    wsize += apache::thrift::util::writeVarint(out_, size);
  }
  return wsize;
}

uint32_t CompactProtocolWriter::writeListBegin(TType elemType, uint32_t size) {
  return writeCollectionBegin(elemType, size);
}

uint32_t CompactProtocolWriter::writeListEnd() {
  return 0;
}

uint32_t CompactProtocolWriter::writeSetBegin(TType elemType, uint32_t size) {
  return writeCollectionBegin(elemType, size);
}

uint32_t CompactProtocolWriter::writeSetEnd() {
  return 0;
}

uint32_t CompactProtocolWriter::writeBool(bool value) {
  uint32_t wsize = 0;

  if (booleanField_.name != NULL) {
    // we haven't written the field header yet
    wsize += writeFieldBeginInternal(
        booleanField_.name,
        booleanField_.fieldType,
        booleanField_.fieldId,
        value ? detail::compact::CT_BOOLEAN_TRUE
              : detail::compact::CT_BOOLEAN_FALSE);
    booleanField_.name = NULL;
  } else {
    // we're not part of a field, so just write the value
    wsize += writeByte(
        value ? detail::compact::CT_BOOLEAN_TRUE
              : detail::compact::CT_BOOLEAN_FALSE);
  }
  return wsize;
}

uint32_t CompactProtocolWriter::writeByte(int8_t byte) {
  out_.write(byte);
  return 1;
}

uint32_t CompactProtocolWriter::writeI16(int16_t i16) {
  uint32_t sz = apache::thrift::util::writeVarint(
      out_, apache::thrift::util::i32ToZigzag(i16));
  return sz;
}

uint32_t CompactProtocolWriter::writeI32(int32_t i32) {
  uint32_t sz = apache::thrift::util::writeVarint(
      out_, apache::thrift::util::i32ToZigzag(i32));
  return sz;
}

uint32_t CompactProtocolWriter::writeI64(int64_t i64) {
  return apache::thrift::util::writeVarint(
      out_, apache::thrift::util::i64ToZigzag(i64));
}

uint32_t CompactProtocolWriter::writeDouble(double dub) {
  static_assert(sizeof(double) == sizeof(uint64_t), "");
  static_assert(std::numeric_limits<double>::is_iec559, "");

  uint64_t bits = bitwise_cast<uint64_t>(dub);
  out_.writeBE(bits);
  return sizeof(bits);
}

uint32_t CompactProtocolWriter::writeFloat(float flt) {
  static_assert(sizeof(float) == sizeof(uint32_t), "");
  static_assert(std::numeric_limits<float>::is_iec559, "");

  uint32_t bits = bitwise_cast<uint32_t>(flt);
  out_.writeBE(bits);
  return sizeof(bits);
}

uint32_t CompactProtocolWriter::writeString(folly::StringPiece str) {
  return writeBinary(str);
}

uint32_t CompactProtocolWriter::writeBinary(folly::StringPiece str) {
  return writeBinary(folly::ByteRange(str));
}

uint32_t CompactProtocolWriter::writeBinary(folly::ByteRange str) {
  uint32_t size = folly::to_narrow(str.size());
  uint32_t result = apache::thrift::util::writeVarint(out_, (int32_t)size);
  out_.push(str.data(), size);
  return result + size;
}

uint32_t CompactProtocolWriter::writeBinary(
    const std::unique_ptr<folly::IOBuf>& str) {
  if (!str) {
    return writeI32(0);
  }
  return writeBinary(*str);
}

uint32_t CompactProtocolWriter::writeBinary(const folly::IOBuf& str) {
  size_t size = str.computeChainDataLength();
  // leave room for varint size
  if (size > std::numeric_limits<uint32_t>::max() - serializedSizeI32()) {
    TProtocolException::throwExceededSizeLimit();
  }
  uint32_t result = apache::thrift::util::writeVarint(out_, (int32_t)size);
  if (sharing_ != SHARE_EXTERNAL_BUFFER && !str.isManaged()) {
    auto clone = str.clone();
    clone->makeManaged();
    out_.insert(std::move(clone));
  } else {
    out_.insert(str);
  }
  return result + static_cast<uint32_t>(size);
}

/**
 * Functions that return the serialized size
 */

uint32_t CompactProtocolWriter::serializedMessageSize(
    folly::StringPiece name) const {
  // I32{version} + String{name} + I32{seqid}
  return 2 * serializedSizeI32() + serializedSizeString(name);
}

uint32_t CompactProtocolWriter::serializedFieldSize(
    const char* /*name*/,
    TType /*fieldType*/,
    int16_t /*fieldId*/) const {
  // byte + I16
  return serializedSizeByte() + serializedSizeI16();
}

uint32_t CompactProtocolWriter::serializedStructSize(
    const char* /*name*/) const {
  return 0;
}

uint32_t CompactProtocolWriter::serializedSizeMapBegin(
    TType /*keyType*/,
    TType /*valType*/,
    uint32_t /*size*/) const {
  return serializedSizeByte() + serializedSizeByte() + serializedSizeI32();
}

uint32_t CompactProtocolWriter::serializedSizeMapEnd() const {
  return 0;
}

uint32_t CompactProtocolWriter::serializedSizeListBegin(
    TType /*elemType*/,
    uint32_t /*size*/) const {
  return serializedSizeByte() + serializedSizeI32();
}

uint32_t CompactProtocolWriter::serializedSizeListEnd() const {
  return 0;
}

uint32_t CompactProtocolWriter::serializedSizeSetBegin(
    TType /*elemType*/,
    uint32_t /*size*/) const {
  return serializedSizeByte() + serializedSizeI32();
}

uint32_t CompactProtocolWriter::serializedSizeSetEnd() const {
  return 0;
}

uint32_t CompactProtocolWriter::serializedSizeStop() const {
  return 1;
}

uint32_t CompactProtocolWriter::serializedSizeBool(bool /* val */) const {
  return 1;
}

uint32_t CompactProtocolWriter::serializedSizeByte(int8_t /* val */) const {
  return 1;
}

// Varint writes can be up to one additional byte
uint32_t CompactProtocolWriter::serializedSizeI16(int16_t /*val*/) const {
  return 3;
}

uint32_t CompactProtocolWriter::serializedSizeI32(int32_t /*val*/) const {
  return 5;
}

uint32_t CompactProtocolWriter::serializedSizeI64(int64_t /*val*/) const {
  return 10;
}

uint32_t CompactProtocolWriter::serializedSizeDouble(double /*val*/) const {
  return 8;
}

uint32_t CompactProtocolWriter::serializedSizeFloat(float /*val*/) const {
  return 4;
}

uint32_t CompactProtocolWriter::serializedSizeString(
    folly::StringPiece str) const {
  return serializedSizeBinary(str);
}

uint32_t CompactProtocolWriter::serializedSizeBinary(
    folly::StringPiece str) const {
  return serializedSizeBinary(folly::ByteRange(str));
}

uint32_t CompactProtocolWriter::serializedSizeBinary(folly::ByteRange v) const {
  // I32{length of string} + binary{string contents}
  return serializedSizeI32() + static_cast<uint32_t>(v.size());
}

uint32_t CompactProtocolWriter::serializedSizeBinary(
    std::unique_ptr<folly::IOBuf> const& v) const {
  return v ? serializedSizeBinary(*v) : 0;
}

uint32_t CompactProtocolWriter::serializedSizeBinary(
    folly::IOBuf const& v) const {
  size_t size = v.computeChainDataLength();
  if (size > std::numeric_limits<uint32_t>::max() - serializedSizeI32()) {
    TProtocolException::throwExceededSizeLimit();
  }
  return serializedSizeI32() + static_cast<uint32_t>(size);
}

uint32_t CompactProtocolWriter::serializedSizeZCBinary(
    folly::StringPiece str) const {
  return serializedSizeZCBinary(folly::ByteRange(str));
}

uint32_t CompactProtocolWriter::serializedSizeZCBinary(
    folly::ByteRange v) const {
  return serializedSizeBinary(v);
}

uint32_t CompactProtocolWriter::serializedSizeZCBinary(
    std::unique_ptr<IOBuf> const& v) const {
  return v ? serializedSizeZCBinary(*v) : 0;
}

uint32_t CompactProtocolWriter::serializedSizeZCBinary(IOBuf const& v) const {
  size_t size = v.computeChainDataLength();
  return (size > folly::IOBufQueue::kMaxPackCopy)
      ? serializedSizeI32() // too big to pack: size only
      : static_cast<uint32_t>(size) + serializedSizeI32(); // size + packed data
}

/**
 * Reading functions
 */

void CompactProtocolReader::readMessageBegin(
    std::string& name,
    MessageType& messageType,
    int32_t& seqid) {
  int8_t protocolId;
  int8_t versionAndType;

  readByte(protocolId);
  if (protocolId != detail::compact::PROTOCOL_ID) {
    throwBadProtocolIdentifier();
  }

  readByte(versionAndType);
  if ((int8_t)(versionAndType & VERSION_MASK) !=
      detail::compact::COMPACT_PROTOCOL_VERSION) {
    throwBadProtocolVersion();
  }

  messageType = (MessageType)(
      (uint8_t)(versionAndType & detail::compact::TYPE_MASK) >>
      detail::compact::TYPE_SHIFT_AMOUNT);
  apache::thrift::util::readVarint(in_, seqid);
  readString(name);
}

void CompactProtocolReader::readMessageEnd() {}

void CompactProtocolReader::readStructBegin(std::string& name) {
  if (!name.empty()) {
    name.clear();
  }
  lastField_.push(lastFieldId_);
  lastFieldId_ = 0;
}

void CompactProtocolReader::readStructEnd() {
  lastFieldId_ = lastField_.top();
  lastField_.pop();
}

void CompactProtocolReader::readFieldBegin(
    std::string& /*name*/,
    TType& fieldType,
    int16_t& fieldId) {
  int8_t byte;
  int8_t type;

  readByte(byte);
  type = (byte & 0x0f);

  // if it's a stop, then we can return immediately, as the struct is over.
  if (type == TType::T_STOP) {
    fieldType = TType::T_STOP;
    fieldId = 0;
    return;
  }

  // mask off the 4 MSB of the type header. it could contain a field id delta.
  int16_t modifier = (int16_t)(((uint8_t)byte & 0xf0) >> 4);
  if (modifier == 0) {
    // not a delta, look ahead for the zigzag varint field id.
    readI16(fieldId);
  } else {
    fieldId = (int16_t)(lastFieldId_ + modifier);
  }
  fieldType = getType(type);

  // if this happens to be a boolean field, the value is encoded in the type
  if (type == detail::compact::CT_BOOLEAN_TRUE ||
      type == detail::compact::CT_BOOLEAN_FALSE) {
    // save the boolean value in a special instance variable.
    boolValue_.hasBoolValue = true;
    boolValue_.boolValue =
        (type == detail::compact::CT_BOOLEAN_TRUE ? true : false);
  }

  // push the new field onto the field stack so we can keep the deltas going.
  lastFieldId_ = fieldId;
}

void CompactProtocolReader::readFieldEnd() {}

void CompactProtocolReader::readMapBegin(
    TType& keyType,
    TType& valType,
    uint32_t& size) {
  int8_t kvType = 0;
  int32_t msize = 0;

  apache::thrift::util::readVarint(in_, msize);
  if (msize != 0) {
    readByte(kvType);
  }

  if (msize < 0) {
    TProtocolException::throwNegativeSize();
  } else if (container_limit_ && msize > container_limit_) {
    TProtocolException::throwExceededSizeLimit();
  }

  keyType = getType((int8_t)((uint8_t)kvType >> 4));
  valType = getType((int8_t)((uint8_t)kvType & 0xf));
  size = (uint32_t)msize;
}

void CompactProtocolReader::readMapEnd() {}

void CompactProtocolReader::readListBegin(TType& elemType, uint32_t& size) {
  int8_t size_and_type;
  int32_t lsize;

  readByte(size_and_type);

  lsize = ((uint8_t)size_and_type >> 4) & 0x0f;
  if (lsize == 15) {
    apache::thrift::util::readVarint(in_, lsize);
  }

  if (lsize < 0) {
    TProtocolException::throwNegativeSize();
  } else if (container_limit_ && lsize > container_limit_) {
    TProtocolException::throwExceededSizeLimit();
  }

  elemType = getType((int8_t)(size_and_type & 0x0f));
  size = (uint32_t)lsize;
}

void CompactProtocolReader::readListEnd() {}

void CompactProtocolReader::readSetBegin(TType& elemType, uint32_t& size) {
  readListBegin(elemType, size);
}

void CompactProtocolReader::readSetEnd() {}

void CompactProtocolReader::readBool(bool& value) {
  if (boolValue_.hasBoolValue == true) {
    value = boolValue_.boolValue;
    boolValue_.hasBoolValue = false;
  } else {
    int8_t val;
    readByte(val);
    value = (val == detail::compact::CT_BOOLEAN_TRUE);
  }
}

void CompactProtocolReader::readBool(std::vector<bool>::reference value) {
  bool ret = false;
  readBool(ret);
  value = ret;
}

void CompactProtocolReader::readByte(int8_t& byte) {
  byte = in_.read<int8_t>();
}

void CompactProtocolReader::readI16(int16_t& i16) {
  int32_t value;
  apache::thrift::util::readVarint(in_, value);
  i16 = (int16_t)apache::thrift::util::zigzagToI32(value);
}

void CompactProtocolReader::readI32(int32_t& i32) {
  int32_t value;
  apache::thrift::util::readVarint(in_, value);
  i32 = apache::thrift::util::zigzagToI32(value);
}

void CompactProtocolReader::readI64(int64_t& i64) {
  uint64_t value;
  apache::thrift::util::readVarint(in_, value);
  i64 = apache::thrift::util::zigzagToI64(value);
}

void CompactProtocolReader::readDouble(double& dub) {
  static_assert(sizeof(double) == sizeof(uint64_t), "");
  static_assert(std::numeric_limits<double>::is_iec559, "");

  uint64_t bits = in_.readBE<int64_t>();
  dub = bitwise_cast<double>(bits);
}

void CompactProtocolReader::readFloat(float& flt) {
  static_assert(sizeof(float) == sizeof(uint32_t), "");
  static_assert(std::numeric_limits<float>::is_iec559, "");

  uint32_t bits = in_.readBE<int32_t>();
  flt = bitwise_cast<float>(bits);
}

void CompactProtocolReader::readStringSize(int32_t& size) {
  apache::thrift::util::readVarint(in_, size);

  // Catch error cases
  if (size < 0) {
    TProtocolException::throwNegativeSize();
  }
  if (string_limit_ > 0 && size > string_limit_) {
    TProtocolException::throwExceededSizeLimit();
  }
}

template <typename StrType>
void CompactProtocolReader::readStringBody(StrType& str, int32_t size) {
  if (static_cast<int32_t>(in_.length()) < size) {
    if (!in_.canAdvance(size)) {
      protocol::TProtocolException::throwTruncatedData();
    }
    str.reserve(size); // only reserve for multi iter case below
  }
  str.clear();
  size_t size_left = size;
  while (size_left > 0) {
    auto data = in_.peekBytes();
    auto data_avail = std::min(data.size(), size_left);
    if (data.empty()) {
      TProtocolException::throwExceededSizeLimit();
    }

    str.append((const char*)data.data(), data_avail);
    size_left -= data_avail;
    in_.skipNoAdvance(data_avail);
  }
}

template <typename StrType>
void CompactProtocolReader::readString(StrType& str) {
  int32_t size = 0;
  readStringSize(size);
  readStringBody(str, size);
}

template <class StrType>
void CompactProtocolReader::readBinary(StrType& str) {
  readString(str);
}

void CompactProtocolReader::readBinary(std::unique_ptr<folly::IOBuf>& str) {
  if (!str) {
    str = std::make_unique<folly::IOBuf>();
  }
  readBinary(*str);
}

void CompactProtocolReader::readBinary(folly::IOBuf& str) {
  int32_t size = 0;
  readStringSize(size);

  in_.clone(str, size);
  if (sharing_ != SHARE_EXTERNAL_BUFFER) {
    str.makeManaged();
  }
}

TType CompactProtocolReader::getType(int8_t type) {
  using detail::compact::CTypeToTType;
  if (LIKELY(
          static_cast<uint8_t>(type) <
          sizeof(CTypeToTType) / sizeof(*CTypeToTType))) {
    return CTypeToTType[type];
  }
  throwBadType(type);
}

FOLLY_ALWAYS_INLINE bool
CompactProtocolReader::matchTypeHeader(uint8_t byte, TType type, uint8_t diff) {
  if (type == TType::T_BOOL) {
    if ((byte == (detail::compact::CT_BOOLEAN_TRUE | (diff << 4))) ||
        (byte == (detail::compact::CT_BOOLEAN_FALSE | (diff << 4)))) {
      boolValue_.hasBoolValue = true;
      boolValue_.boolValue = byte & 1;
      return true;
    }
    return false;
  } else {
    return byte == (detail::compact::TTypeToCType[type] | (diff << 4));
  }
}

bool CompactProtocolReader::advanceToNextField(
    int32_t currFieldId,
    int32_t nextFieldId,
    TType nextFieldType,
    StructReadState& state) {
  if (in_.length()) {
    if (nextFieldType == TType::T_STOP) {
      if (*in_.data() == TType::T_STOP) {
        in_.skipNoAdvance(1);
        return true;
      }
    } else if (nextFieldId > currFieldId && (nextFieldId - currFieldId <= 15)) {
      if (matchTypeHeader(
              *in_.data(), nextFieldType, nextFieldId - currFieldId)) {
        in_.skipNoAdvance(1);
        return true;
      }
    } else if (matchTypeHeader(*in_.data(), nextFieldType, 0)) {
      // In one byte, we can fit values up to 127 (7-bit, due to varint),
      // which corresponds to a range [-64; 63] with zigzag encoding.
      // In two bytes, we can fit values up to 16383 (14-bit), which corresponds
      // to a range [-8192; 8191] with zigzag encoding.
      if (nextFieldId >= -64 && nextFieldId <= 63) {
        if (in_.length() > 1 &&
            *(in_.data() + 1) ==
                static_cast<uint8_t>(util::i32ToZigzag(nextFieldId))) {
          in_.skipNoAdvance(2);
          return true;
        }
      } else if (nextFieldId >= -8192 && nextFieldId <= 8191) {
        if (in_.length() > 2 &&
            *(in_.data() + 1) ==
                ((util::i32ToZigzag(nextFieldId) & 0x7F) | 0x80) &&
            *(in_.data() + 2) ==
                ((util::i32ToZigzag(nextFieldId) & 0x3F80) >> 7)) {
          in_.skipNoAdvance(3);
          return true;
        }
      } else {
        if (in_.length() > 3 &&
            *(in_.data() + 1) ==
                ((util::i32ToZigzag(nextFieldId) & 0x7F) | 0x80) &&
            *(in_.data() + 2) ==
                ((util::i32ToZigzag(nextFieldId) & 0x3F80) >> 7 | 0x80) &&
            *(in_.data() + 3) ==
                ((util::i32ToZigzag(nextFieldId) & 0x1FC000) >> 14)) {
          in_.skipNoAdvance(4);
          return true;
        }
      }
    }

    readFieldBeginWithStateMediumSlow(state, currFieldId);
  } else {
    // We're out of luck, fallback to slow path.
    state.fieldId = currFieldId;
    state.readFieldBeginNoInline(this);
  }
  return false;
}

void CompactProtocolReader::readStructBeginWithState(
    StructReadState& /* state */) {}

void CompactProtocolReader::readFieldBeginWithState(StructReadState& state) {
  int8_t byte;
  readByte(byte);
  readFieldBeginWithStateImpl(state, state.fieldId, byte);
}

FOLLY_ALWAYS_INLINE void CompactProtocolReader::readFieldBeginWithStateImpl(
    StructReadState& state,
    int16_t prevFieldId,
    uint8_t firstByte) {
  if (firstByte == detail::compact::CT_STOP) {
    state.fieldType = TType::T_STOP;
    return;
  }

  int16_t modifier = (firstByte & 0xf0) >> 4;
  if (modifier != 0) {
    state.fieldId = prevFieldId + modifier;
  } else {
    // not a delta, look ahead for the zigzag varint field id.
    readI16(state.fieldId);
  }

  uint8_t type = firstByte & 0xf;
  state.fieldType = getType(type);

  // if this happens to be a boolean field, the value is encoded in the type
  if (type == detail::compact::CT_BOOLEAN_TRUE ||
      type == detail::compact::CT_BOOLEAN_FALSE) {
    // save the boolean value in a special instance variable.
    boolValue_.hasBoolValue = true;
    boolValue_.boolValue = type == detail::compact::CT_BOOLEAN_TRUE;
  }
}

} // namespace thrift
} // namespace apache

#endif // #ifndef THRIFT2_PROTOCOL_COMPACTPROTOCOL_TCC_
