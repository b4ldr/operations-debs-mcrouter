/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */

package test.fixtures.sink;

import com.facebook.swift.codec.*;
import com.facebook.swift.codec.ThriftField.Requiredness;
import com.facebook.swift.service.*;
import com.google.common.util.concurrent.ListenableFuture;
import java.io.*;
import java.util.*;

@SwiftGenerated
@ThriftService("SinkService")
public interface SinkService extends java.io.Closeable {
    @ThriftService("SinkService")
    public interface Async extends java.io.Closeable {
        @Override void close();

    }
    @Override void close();

    @ThriftMethod(value = "method")
     method() throws org.apache.thrift.TException;

    @ThriftMethod(value = "methodAndReponse")
     methodAndReponse() throws org.apache.thrift.TException;

    @ThriftMethod(value = "methodThrow",
                  exception = { 
                      @ThriftException(type=test.fixtures.sink.InitialException.class, id=1)
                  })
     methodThrow() throws test.fixtures.sink.InitialException, org.apache.thrift.TException;

    @ThriftMethod(value = "methodSinkThrow")
     methodSinkThrow() throws org.apache.thrift.TException;

    @ThriftMethod(value = "methodFinalThrow")
     methodFinalThrow() throws org.apache.thrift.TException;

    @ThriftMethod(value = "methodBothThrow")
     methodBothThrow() throws org.apache.thrift.TException;
}
