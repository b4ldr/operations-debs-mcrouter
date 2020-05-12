/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */

package test.fixtures.basicannotations;

import com.facebook.swift.codec.*;
import com.facebook.swift.codec.ThriftField.Requiredness;
import com.facebook.swift.service.*;
import com.google.common.util.concurrent.ListenableFuture;
import java.io.*;
import java.util.*;

@SwiftGenerated
@ThriftService("MyService")
public interface MyService extends java.io.Closeable {
    @ThriftService("MyService")
    public interface Async extends java.io.Closeable {
        @Override void close();

        @ThriftMethod(value = "ping")
        ListenableFuture<Void> ping();

        @ThriftMethod(value = "getRandomData")
        ListenableFuture<String> getRandomData();

        @ThriftMethod(value = "hasDataById")
        ListenableFuture<Boolean> hasDataById(
            @ThriftField(value=1, name="id", requiredness=Requiredness.NONE) final long id);

        @ThriftMethod(value = "getDataById")
        ListenableFuture<String> getDataById(
            @ThriftField(value=1, name="id", requiredness=Requiredness.NONE) final long id);

        @ThriftMethod(value = "putDataById")
        ListenableFuture<Void> putDataById(
            @ThriftField(value=1, name="id", requiredness=Requiredness.NONE) final long id,
            @ThriftField(value=2, name="data", requiredness=Requiredness.NONE) final String data);

        @ThriftMethod(value = "lobDataById",
                      oneway = true)
        ListenableFuture<Void> lobDataById(
            @ThriftField(value=1, name="id", requiredness=Requiredness.NONE) final long id,
            @ThriftField(value=2, name="data", requiredness=Requiredness.NONE) final String data);

        @ThriftMethod(value = "doNothing")
        ListenableFuture<Void> doNothing();
    }
    @Override void close();

    @ThriftMethod(value = "ping")
    void ping() throws org.apache.thrift.TException;

    @ThriftMethod(value = "getRandomData")
    String getRandomData() throws org.apache.thrift.TException;

    @ThriftMethod(value = "hasDataById")
    boolean hasDataById(
        @ThriftField(value=1, name="id", requiredness=Requiredness.NONE) final long id) throws org.apache.thrift.TException;

    @ThriftMethod(value = "getDataById")
    String getDataById(
        @ThriftField(value=1, name="id", requiredness=Requiredness.NONE) final long id) throws org.apache.thrift.TException;

    @ThriftMethod(value = "putDataById")
    void putDataById(
        @ThriftField(value=1, name="id", requiredness=Requiredness.NONE) final long id,
        @ThriftField(value=2, name="data", requiredness=Requiredness.NONE) final String data) throws org.apache.thrift.TException;

    @ThriftMethod(value = "lobDataById",
                  oneway = true)
    void lobDataById(
        @ThriftField(value=1, name="id", requiredness=Requiredness.NONE) final long id,
        @ThriftField(value=2, name="data", requiredness=Requiredness.NONE) final String data) throws org.apache.thrift.TException;

    @ThriftMethod(value = "doNothing")
    void doNothing() throws org.apache.thrift.TException;
}
