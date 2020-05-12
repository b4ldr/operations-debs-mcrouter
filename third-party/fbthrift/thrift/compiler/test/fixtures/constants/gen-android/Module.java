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
    Internship, Range, struct1, struct2, struct3, union1, union2;
  }

  public static final ThriftProperty<Integer> Internship_weeks =
      new ThriftProperty<Integer>("weeks", TType.I32, (short) 1);
  public static final ThriftProperty<String> Internship_title =
      new ThriftProperty<String>("title", TType.STRING, (short) 2);
  public static final ThriftProperty<ModuleEnum> Internship_employer =
      new ThriftProperty<ModuleEnum>("employer", TType.I32, (short) 3);
  public static final ThriftProperty<Integer> Range_min =
      new ThriftProperty<Integer>("min", TType.I32, (short) 1);
  public static final ThriftProperty<Integer> Range_max =
      new ThriftProperty<Integer>("max", TType.I32, (short) 2);
  public static final ThriftProperty<Integer> struct1_a =
      new ThriftProperty<Integer>("a", TType.I32, (short) 1);
  public static final ThriftProperty<String> struct1_b =
      new ThriftProperty<String>("b", TType.STRING, (short) 2);
  public static final ThriftProperty<Integer> struct2_a =
      new ThriftProperty<Integer>("a", TType.I32, (short) 1);
  public static final ThriftProperty<String> struct2_b =
      new ThriftProperty<String>("b", TType.STRING, (short) 2);
  public static final ThriftProperty<ModuleLogger> struct2_c =
      new ThriftProperty<ModuleLogger>("c", TType.STRUCT, (short) 3);
  public static final ThriftProperty<List<Integer>> struct2_d =
      new ThriftProperty<List<Integer>>("d", TType.LIST, (short) 4);
  public static final ThriftProperty<String> struct3_a =
      new ThriftProperty<String>("a", TType.STRING, (short) 1);
  public static final ThriftProperty<Integer> struct3_b =
      new ThriftProperty<Integer>("b", TType.I32, (short) 2);
  public static final ThriftProperty<ModuleLogger> struct3_c =
      new ThriftProperty<ModuleLogger>("c", TType.STRUCT, (short) 3);
  public static final ThriftProperty<Integer> union1_i =
      new ThriftProperty<Integer>("i", TType.I32, (short) 1);
  public static final ThriftProperty<Double> union1_d =
      new ThriftProperty<Double>("d", TType.DOUBLE, (short) 2);
  public static final ThriftProperty<Integer> union2_i =
      new ThriftProperty<Integer>("i", TType.I32, (short) 1);
  public static final ThriftProperty<Double> union2_d =
      new ThriftProperty<Double>("d", TType.DOUBLE, (short) 2);
  public static final ThriftProperty<ModuleLogger> union2_s =
      new ThriftProperty<ModuleLogger>("s", TType.STRUCT, (short) 3);
  public static final ThriftProperty<ModuleLogger> union2_u =
      new ThriftProperty<ModuleLogger>("u", TType.STRUCT, (short) 4);
  
}