/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */


import java.util.List;

import com.facebook.thrift.lite.*;
import com.facebook.thrift.lite.protocol.*;


public class Module {

  public enum EventType {
    ComplexUnion, ListUnion, DataUnion, Val, ValUnion, VirtualComplexUnion, NonCopyableStruct, NonCopyableUnion;
  }

  public static final ThriftProperty<Long> ComplexUnion_intValue =
      new ThriftProperty<Long>("intValue", TType.I64, (short) 1);
  public static final ThriftProperty<String> ComplexUnion_stringValue =
      new ThriftProperty<String>("stringValue", TType.STRING, (short) 5);
  public static final ThriftProperty<List<Long>> ComplexUnion_intListValue =
      new ThriftProperty<List<Long>>("intListValue", TType.LIST, (short) 2);
  public static final ThriftProperty<List<String>> ComplexUnion_stringListValue =
      new ThriftProperty<List<String>>("stringListValue", TType.LIST, (short) 3);
  public static final ThriftProperty<Map<Short,String>> ComplexUnion_typedefValue =
      new ThriftProperty<Map<Short,String>>("typedefValue", TType.MAP, (short) 9);
  public static final ThriftProperty<String> ComplexUnion_stringRef =
      new ThriftProperty<String>("stringRef", TType.STRING, (short) 14);
  public static final ThriftProperty<List<Long>> ListUnion_intListValue =
      new ThriftProperty<List<Long>>("intListValue", TType.LIST, (short) 2);
  public static final ThriftProperty<List<String>> ListUnion_stringListValue =
      new ThriftProperty<List<String>>("stringListValue", TType.LIST, (short) 3);
  public static final ThriftProperty<byte[]> DataUnion_binaryData =
      new ThriftProperty<byte[]>("binaryData", TType.STRING, (short) 1);
  public static final ThriftProperty<String> DataUnion_stringData =
      new ThriftProperty<String>("stringData", TType.STRING, (short) 2);
  public static final ThriftProperty<String> Val_strVal =
      new ThriftProperty<String>("strVal", TType.STRING, (short) 1);
  public static final ThriftProperty<Integer> Val_intVal =
      new ThriftProperty<Integer>("intVal", TType.I32, (short) 2);
  public static final ThriftProperty<Map<Short,String>> Val_typedefValue =
      new ThriftProperty<Map<Short,String>>("typedefValue", TType.MAP, (short) 9);
  public static final ThriftProperty<ModuleLogger> ValUnion_v1 =
      new ThriftProperty<ModuleLogger>("v1", TType.STRUCT, (short) 1);
  public static final ThriftProperty<ModuleLogger> ValUnion_v2 =
      new ThriftProperty<ModuleLogger>("v2", TType.STRUCT, (short) 2);
  public static final ThriftProperty<String> VirtualComplexUnion_thingOne =
      new ThriftProperty<String>("thingOne", TType.STRING, (short) 1);
  public static final ThriftProperty<String> VirtualComplexUnion_thingTwo =
      new ThriftProperty<String>("thingTwo", TType.STRING, (short) 2);
  public static final ThriftProperty<Long> NonCopyableStruct_num =
      new ThriftProperty<Long>("num", TType.I64, (short) 1);
  public static final ThriftProperty<ModuleLogger> NonCopyableUnion_s =
      new ThriftProperty<ModuleLogger>("s", TType.STRUCT, (short) 1);
  
}