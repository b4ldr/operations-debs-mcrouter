/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */

package test.fixtures.basicannotations;

import com.facebook.swift.codec.*;
import com.facebook.swift.codec.ThriftField.Requiredness;
import com.facebook.swift.codec.ThriftField.Recursiveness;
import com.google.common.collect.*;
import java.util.*;
import org.apache.thrift.*;
import org.apache.thrift.async.*;
import org.apache.thrift.meta_data.*;
import org.apache.thrift.server.*;
import org.apache.thrift.transport.*;
import org.apache.thrift.protocol.*;
import org.apache.thrift.meta_data.FieldMetaData;
import org.apache.thrift.meta_data.FieldValueMetaData;
import static com.google.common.base.MoreObjects.toStringHelper;
import static com.google.common.base.MoreObjects.ToStringHelper;

@SwiftGenerated
@ThriftStruct(value="MyStruct", builder=MyStruct.Builder.class)
public final class MyStruct {
    @ThriftConstructor
    public MyStruct(
        @ThriftField(value=1, name="major", requiredness=Requiredness.NONE) final long major,
        @ThriftField(value=2, name="package", requiredness=Requiredness.NONE) final String _package,
        @ThriftField(value=3, name="annotation_with_quote", requiredness=Requiredness.NONE) final String annotationWithQuote,
        @ThriftField(value=4, name="class_", requiredness=Requiredness.NONE) final String class_
    ) {
        this.major = major;
        this._package = _package;
        this.annotationWithQuote = annotationWithQuote;
        this.class_ = class_;
    }
    
    @ThriftConstructor
    protected MyStruct() {
      this.major = 0L;
      this._package = null;
      this.annotationWithQuote = null;
      this.class_ = null;
    }
    
    public static class Builder {
        private long major = 0L;
        private String _package = null;
        private String annotationWithQuote = null;
        private String class_ = null;
    
        @ThriftField(value=1, name="major", requiredness=Requiredness.NONE)
        public Builder setMajor(long major) {
            this.major = major;
            return this;
        }
        
        public long getMajor() { return major; }
    
            @ThriftField(value=2, name="package", requiredness=Requiredness.NONE)
        public Builder setPackage(String _package) {
            this._package = _package;
            return this;
        }
        
        public String getPackage() { return _package; }
    
            @ThriftField(value=3, name="annotation_with_quote", requiredness=Requiredness.NONE)
        public Builder setAnnotationWithQuote(String annotationWithQuote) {
            this.annotationWithQuote = annotationWithQuote;
            return this;
        }
        
        public String getAnnotationWithQuote() { return annotationWithQuote; }
    
            @ThriftField(value=4, name="class_", requiredness=Requiredness.NONE)
        public Builder setClass_(String class_) {
            this.class_ = class_;
            return this;
        }
        
        public String getClass_() { return class_; }
    
        public Builder() { }
        public Builder(MyStruct other) {
            this.major = other.major;
            this._package = other._package;
            this.annotationWithQuote = other.annotationWithQuote;
            this.class_ = other.class_;
        }
    
        @ThriftConstructor
        public MyStruct build() {
            return new MyStruct (
                this.major,
                this._package,
                this.annotationWithQuote,
                this.class_
            );
        }
    }
    
    private static final TStruct STRUCT_DESC = new TStruct("MyStruct");
    private final long major;
    public static final int _MAJOR = 1;
    private static final TField MAJOR_FIELD_DESC = new TField("major", TType.I64, (short)1);
    private final String _package;
    public static final int _PACKAGE = 2;
    private static final TField PACKAGE_FIELD_DESC = new TField("_package", TType.STRING, (short)2);
    private final String annotationWithQuote;
    public static final int _ANNOTATION_WITH_QUOTE = 3;
    private static final TField ANNOTATION_WITH_QUOTE_FIELD_DESC = new TField("annotationWithQuote", TType.STRING, (short)3);
    private final String class_;
    public static final int _CLASS_ = 4;
    private static final TField CLASS__FIELD_DESC = new TField("class_", TType.STRING, (short)4);

    
    @ThriftField(value=1, name="major", requiredness=Requiredness.NONE)
    public long getMajor() { return major; }
        
    @ThriftField(value=2, name="package", requiredness=Requiredness.NONE)
    public String getPackage() { return _package; }
        
    @ThriftField(value=3, name="annotation_with_quote", requiredness=Requiredness.NONE)
    public String getAnnotationWithQuote() { return annotationWithQuote; }
        
    @ThriftField(value=4, name="class_", requiredness=Requiredness.NONE)
    public String getClass_() { return class_; }
    
    @Override
    public String toString() {
        ToStringHelper helper = toStringHelper(this);
        helper.add("major", major);
        helper.add("_package", _package);
        helper.add("annotationWithQuote", annotationWithQuote);
        helper.add("class_", class_);
        return helper.toString();
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
    
        MyStruct other = (MyStruct)o;
    
        return
            Objects.equals(major, other.major) &&
            Objects.equals(_package, other._package) &&
            Objects.equals(annotationWithQuote, other.annotationWithQuote) &&
            Objects.equals(class_, other.class_) &&
            true;
    }
    
    @Override
    public int hashCode() {
        return Arrays.deepHashCode(new Object[] {
            major,
            _package,
            annotationWithQuote,
            class_
        });
    }
    
    
      // Currently, the read0 method cannot read metadatamap for JSON styled serialization.
      // Perhaps, it will be implemented in the future!
    public static MyStruct read0(TProtocol oprot) throws TException {
      TField __field;
      oprot.readStructBegin();
      MyStruct.Builder builder = new MyStruct.Builder();
      while (true) {
        __field = oprot.readFieldBegin();
        if (__field.type == TType.STOP) { break; }
        switch (__field.id) {
        case _MAJOR:
          if (__field.type == TType.I64) {
            long major = oprot.readI64();
            builder.setMajor(major);
          } else {
            TProtocolUtil.skip(oprot, __field.type);
          }
          break;
        case _PACKAGE:
          if (__field.type == TType.STRING) {
            String _package = oprot.readString();
            builder.setPackage(_package);
          } else {
            TProtocolUtil.skip(oprot, __field.type);
          }
          break;
        case _ANNOTATION_WITH_QUOTE:
          if (__field.type == TType.STRING) {
            String annotationWithQuote = oprot.readString();
            builder.setAnnotationWithQuote(annotationWithQuote);
          } else {
            TProtocolUtil.skip(oprot, __field.type);
          }
          break;
        case _CLASS_:
          if (__field.type == TType.STRING) {
            String class_ = oprot.readString();
            builder.setClass_(class_);
          } else {
            TProtocolUtil.skip(oprot, __field.type);
          }
          break;
        default:
          TProtocolUtil.skip(oprot, __field.type);
          break;
        }
        oprot.readFieldEnd();
      }
      oprot.readStructEnd();
      return builder.build();
    }
    
    public void write0(TProtocol oprot) throws TException {
      oprot.writeStructBegin(STRUCT_DESC);
      oprot.writeFieldBegin(MAJOR_FIELD_DESC);
      oprot.writeI64(this.major);
      oprot.writeFieldEnd();
      if (this._package != null) {
        oprot.writeFieldBegin(PACKAGE_FIELD_DESC);
        oprot.writeString(this._package);
        oprot.writeFieldEnd();
      }
      if (this.annotationWithQuote != null) {
        oprot.writeFieldBegin(ANNOTATION_WITH_QUOTE_FIELD_DESC);
        oprot.writeString(this.annotationWithQuote);
        oprot.writeFieldEnd();
      }
      if (this.class_ != null) {
        oprot.writeFieldBegin(CLASS__FIELD_DESC);
        oprot.writeString(this.class_);
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }
    
}
