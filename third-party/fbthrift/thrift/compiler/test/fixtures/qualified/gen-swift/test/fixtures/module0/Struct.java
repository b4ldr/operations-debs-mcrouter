/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */

package test.fixtures.module0;

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
@ThriftStruct(value="Struct", builder=Struct.Builder.class)
public final class Struct {
    @ThriftConstructor
    public Struct(
        @ThriftField(value=1, name="first", requiredness=Requiredness.NONE) final int first,
        @ThriftField(value=2, name="second", requiredness=Requiredness.NONE) final String second
    ) {
        this.first = first;
        this.second = second;
    }
    
    @ThriftConstructor
    protected Struct() {
      this.first = 0;
      this.second = null;
    }
    
    public static class Builder {
        private int first = 0;
        private String second = null;
    
        @ThriftField(value=1, name="first", requiredness=Requiredness.NONE)
        public Builder setFirst(int first) {
            this.first = first;
            return this;
        }
        
        public int getFirst() { return first; }
    
            @ThriftField(value=2, name="second", requiredness=Requiredness.NONE)
        public Builder setSecond(String second) {
            this.second = second;
            return this;
        }
        
        public String getSecond() { return second; }
    
        public Builder() { }
        public Builder(Struct other) {
            this.first = other.first;
            this.second = other.second;
        }
    
        @ThriftConstructor
        public Struct build() {
            return new Struct (
                this.first,
                this.second
            );
        }
    }
    
    private static final TStruct STRUCT_DESC = new TStruct("Struct");
    private final int first;
    public static final int _FIRST = 1;
    private static final TField FIRST_FIELD_DESC = new TField("first", TType.I32, (short)1);
    private final String second;
    public static final int _SECOND = 2;
    private static final TField SECOND_FIELD_DESC = new TField("second", TType.STRING, (short)2);

    
    @ThriftField(value=1, name="first", requiredness=Requiredness.NONE)
    public int getFirst() { return first; }
        
    @ThriftField(value=2, name="second", requiredness=Requiredness.NONE)
    public String getSecond() { return second; }
    
    @Override
    public String toString() {
        ToStringHelper helper = toStringHelper(this);
        helper.add("first", first);
        helper.add("second", second);
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
    
        Struct other = (Struct)o;
    
        return
            Objects.equals(first, other.first) &&
            Objects.equals(second, other.second) &&
            true;
    }
    
    @Override
    public int hashCode() {
        return Arrays.deepHashCode(new Object[] {
            first,
            second
        });
    }
    
    
      // Currently, the read0 method cannot read metadatamap for JSON styled serialization.
      // Perhaps, it will be implemented in the future!
    public static Struct read0(TProtocol oprot) throws TException {
      TField __field;
      oprot.readStructBegin();
      Struct.Builder builder = new Struct.Builder();
      while (true) {
        __field = oprot.readFieldBegin();
        if (__field.type == TType.STOP) { break; }
        switch (__field.id) {
        case _FIRST:
          if (__field.type == TType.I32) {
            int first = oprot.readI32();
            builder.setFirst(first);
          } else {
            TProtocolUtil.skip(oprot, __field.type);
          }
          break;
        case _SECOND:
          if (__field.type == TType.STRING) {
            String second = oprot.readString();
            builder.setSecond(second);
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
      oprot.writeFieldBegin(FIRST_FIELD_DESC);
      oprot.writeI32(this.first);
      oprot.writeFieldEnd();
      if (this.second != null) {
        oprot.writeFieldBegin(SECOND_FIELD_DESC);
        oprot.writeString(this.second);
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }
    
}
