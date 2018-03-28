/*
 *  Copyright (c) 2017-present, Facebook, Inc.
 *
 *  This source code is licensed under the MIT license found in the LICENSE
 *  file in the root directory of this source tree.
 *
 */

/*
 *  THIS FILE IS AUTOGENERATED. DO NOT MODIFY IT; ALL CHANGES WILL BE LOST IN
 *  VAIN.
 *
 *  @generated
 */

namespace facebook {
namespace memcache {

template <class V>
void McVersionRequest::visitFields(V&& v) {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McVersionRequest::visitFields(V&& v) const {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McVersionReply::visitFields(V&& v) {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "value", value_)) {
    return;
  }
  if (!v.visitField(3, "message", message_)) {
    return;
  }
  if (!v.visitField(4, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McVersionReply::visitFields(V&& v) const {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "value", value_)) {
    return;
  }
  if (!v.visitField(3, "message", message_)) {
    return;
  }
  if (!v.visitField(4, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McStatsRequest::visitFields(V&& v) {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McStatsRequest::visitFields(V&& v) const {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McStatsReply::visitFields(V&& v) {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "message", message_)) {
    return;
  }
  if (!v.visitField(3, "stats", stats_)) {
    return;
  }
  if (!v.visitField(4, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McStatsReply::visitFields(V&& v) const {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "message", message_)) {
    return;
  }
  if (!v.visitField(3, "stats", stats_)) {
    return;
  }
  if (!v.visitField(4, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McShutdownRequest::visitFields(V&& v) {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McShutdownRequest::visitFields(V&& v) const {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McShutdownReply::visitFields(V&& v) {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "message", message_)) {
    return;
  }
  if (!v.visitField(3, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McShutdownReply::visitFields(V&& v) const {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "message", message_)) {
    return;
  }
  if (!v.visitField(3, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McQuitRequest::visitFields(V&& v) {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McQuitRequest::visitFields(V&& v) const {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McQuitReply::visitFields(V&& v) {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "message", message_)) {
    return;
  }
  if (!v.visitField(3, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McQuitReply::visitFields(V&& v) const {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "message", message_)) {
    return;
  }
  if (!v.visitField(3, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McExecRequest::visitFields(V&& v) {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McExecRequest::visitFields(V&& v) const {
  if (!v.visitField(1, "key", key_)) {
    return;
  }
}

template <class V>
void McExecReply::visitFields(V&& v) {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "response", response_)) {
    return;
  }
  if (!v.visitField(3, "message", message_)) {
    return;
  }
  if (!v.visitField(4, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void McExecReply::visitFields(V&& v) const {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "response", response_)) {
    return;
  }
  if (!v.visitField(3, "message", message_)) {
    return;
  }
  if (!v.visitField(4, "appSpecificErrorCode", appSpecificErrorCode_)) {
    return;
  }
}

template <class V>
void GoAwayAcknowledgement::visitFields(V&&) {}

template <class V>
void GoAwayAcknowledgement::visitFields(V&&) const {}

template <class V>
void GoAwayRequest::visitFields(V&& v) {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "reason", reason_)) {
    return;
  }
}

template <class V>
void GoAwayRequest::visitFields(V&& v) const {
  if (!v.visitField(1, "result", result_)) {
    return;
  }
  if (!v.visitField(2, "reason", reason_)) {
    return;
  }
}

} // namespace memcache
} // namespace facebook