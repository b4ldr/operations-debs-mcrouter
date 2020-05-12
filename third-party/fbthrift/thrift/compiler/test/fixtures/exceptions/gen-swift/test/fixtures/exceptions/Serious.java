/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */

package test.fixtures.exceptions;

import com.facebook.swift.codec.*;
import com.facebook.swift.codec.ThriftField.Requiredness;
import com.facebook.swift.codec.ThriftField.Recursiveness;
import java.util.*;
import org.apache.thrift.*;
import org.apache.thrift.async.*;
import org.apache.thrift.meta_data.*;
import org.apache.thrift.server.*;
import org.apache.thrift.transport.*;
import org.apache.thrift.protocol.*;
import org.apache.thrift.meta_data.FieldMetaData;
import org.apache.thrift.meta_data.FieldValueMetaData;

@SwiftGenerated
@ThriftStruct("Serious")
public final class Serious extends java.lang.RuntimeException {
    private static final long serialVersionUID = 1L;

    private static final TStruct STRUCT_DESC = new TStruct("Serious");
    private final String sonnet;
    public static final int _SONNET = 1;
    private static final TField SONNET_FIELD_DESC = new TField("sonnet", TType.STRING, (short)1);

    @ThriftConstructor
    public Serious(
        @ThriftField(value=1, name="sonnet", requiredness=Requiredness.OPTIONAL) final String sonnet
    ) {
        this.sonnet = sonnet;
    }
    
    @ThriftConstructor
    protected Serious() {
      this.sonnet = null;
    }
    
    public static class Builder {
        private String sonnet = null;
    
        @ThriftField(value=1, name="sonnet", requiredness=Requiredness.OPTIONAL)
        public Builder setSonnet(String sonnet) {
            this.sonnet = sonnet;
            return this;
        }
        
        public String getSonnet() { return sonnet; }
    
        public Builder() { }
        public Builder(Serious other) {
            this.sonnet = other.sonnet;
        }
    
        @ThriftConstructor
        public Serious build() {
            return new Serious (
                this.sonnet
            );
        }
    }
    
    
    @ThriftField(value=1, name="sonnet", requiredness=Requiredness.OPTIONAL)
    public String getSonnet() { return sonnet; }
    
    
      // Currently, the read0 method cannot read metadatamap for JSON styled serialization.
      // Perhaps, it will be implemented in the future!
    public static Serious read0(TProtocol oprot) throws TException {
      TField __field;
      oprot.readStructBegin();
      Serious.Builder builder = new Serious.Builder();
      while (true) {
        __field = oprot.readFieldBegin();
        if (__field.type == TType.STOP) { break; }
        switch (__field.id) {
        case _SONNET:
          if (__field.type == TType.STRING) {
            String sonnet = oprot.readString();
            builder.setSonnet(sonnet);
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
      if (this.sonnet != null) {
        oprot.writeFieldBegin(SONNET_FIELD_DESC);
        oprot.writeString(this.sonnet);
        oprot.writeFieldEnd();
      }
      oprot.writeFieldStop();
      oprot.writeStructEnd();
    }
    
}
