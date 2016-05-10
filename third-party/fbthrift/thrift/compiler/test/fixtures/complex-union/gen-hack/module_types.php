<?hh
/**
 * Autogenerated by Thrift
 *
 * DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
 *  @generated
 */

enum ComplexUnionEnum: int {
  _EMPTY_ = 0;
  intValue = 1;
  stringValue = 2;
  intListValue = 3;
  stringListValue = 4;
  stringRef = 5;
}

class ComplexUnion implements IThriftStruct, IThriftUnion<ComplexUnionEnum> {
  public static array $_TSPEC = array(
    1 => array(
      'var' => 'intValue',
      'union' => true,
      'type' => TType::I64,
      ),
    2 => array(
      'var' => 'stringValue',
      'union' => true,
      'type' => TType::STRING,
      ),
    3 => array(
      'var' => 'intListValue',
      'union' => true,
      'type' => TType::LST,
      'etype' => TType::I64,
      'elem' => array(
        'type' => TType::I64,
        ),
        'format' => 'collection',
      ),
    4 => array(
      'var' => 'stringListValue',
      'union' => true,
      'type' => TType::LST,
      'etype' => TType::STRING,
      'elem' => array(
        'type' => TType::STRING,
        ),
        'format' => 'collection',
      ),
    5 => array(
      'var' => 'stringRef',
      'union' => true,
      'type' => TType::STRING,
      ),
    );
  public static Map<string, int> $_TFIELDMAP = Map {
    'intValue' => 1,
    'stringValue' => 2,
    'intListValue' => 3,
    'stringListValue' => 4,
    'stringRef' => 5,
  };
  const int STRUCTURAL_ID = 6550502502248501709;
  public ?int $intValue;
  public ?string $stringValue;
  public ?Vector<int> $intListValue;
  public ?Vector<string> $stringListValue;
  public ?string $stringRef;
  protected ComplexUnionEnum $_type = ComplexUnionEnum::_EMPTY_;

  public function __construct(?int $intValue = null, ?string $stringValue = null, ?Vector<int> $intListValue = null, ?Vector<string> $stringListValue = null, ?string $stringRef = null  ) {
    $this->_type = ComplexUnionEnum::_EMPTY_;
    if ($intValue !== null) {
      $this->intValue = $intValue;
      $this->_type = ComplexUnionEnum::intValue;
    }
    if ($stringValue !== null) {
      $this->stringValue = $stringValue;
      $this->_type = ComplexUnionEnum::stringValue;
    }
    if ($intListValue !== null) {
      $this->intListValue = $intListValue;
      $this->_type = ComplexUnionEnum::intListValue;
    }
    if ($stringListValue !== null) {
      $this->stringListValue = $stringListValue;
      $this->_type = ComplexUnionEnum::stringListValue;
    }
    if ($stringRef !== null) {
      $this->stringRef = $stringRef;
      $this->_type = ComplexUnionEnum::stringRef;
    }
  }

  public function getName(): string {
    return 'ComplexUnion';
  }

  public function getType(): ComplexUnionEnum {
    return $this->_type;
  }

  public function set_intValue(int $intValue): this {
    $this->_type = ComplexUnionEnum::intValue;
    $this->intValue = $intValue;
    return $this;
  }

  public function get_intValue(): int {
    invariant($this->_type === ComplexUnionEnum::intValue,
      'get_intValue called on an instance of ComplexUnion whose current type is' . $this->_type);
    return nullthrows($this->intValue);
  }

  public function set_stringValue(string $stringValue): this {
    $this->_type = ComplexUnionEnum::stringValue;
    $this->stringValue = $stringValue;
    return $this;
  }

  public function get_stringValue(): string {
    invariant($this->_type === ComplexUnionEnum::stringValue,
      'get_stringValue called on an instance of ComplexUnion whose current type is' . $this->_type);
    return nullthrows($this->stringValue);
  }

  public function set_intListValue(Vector<int> $intListValue): this {
    $this->_type = ComplexUnionEnum::intListValue;
    $this->intListValue = $intListValue;
    return $this;
  }

  public function get_intListValue(): Vector<int> {
    invariant($this->_type === ComplexUnionEnum::intListValue,
      'get_intListValue called on an instance of ComplexUnion whose current type is' . $this->_type);
    return nullthrows($this->intListValue);
  }

  public function set_stringListValue(Vector<string> $stringListValue): this {
    $this->_type = ComplexUnionEnum::stringListValue;
    $this->stringListValue = $stringListValue;
    return $this;
  }

  public function get_stringListValue(): Vector<string> {
    invariant($this->_type === ComplexUnionEnum::stringListValue,
      'get_stringListValue called on an instance of ComplexUnion whose current type is' . $this->_type);
    return nullthrows($this->stringListValue);
  }

  public function set_stringRef(string $stringRef): this {
    $this->_type = ComplexUnionEnum::stringRef;
    $this->stringRef = $stringRef;
    return $this;
  }

  public function get_stringRef(): string {
    invariant($this->_type === ComplexUnionEnum::stringRef,
      'get_stringRef called on an instance of ComplexUnion whose current type is' . $this->_type);
    return nullthrows($this->stringRef);
  }

  public function read(TProtocol $input): int {
    $xfer = 0;
    $fname = '';
    $ftype = 0;
    $fid = 0;
    $this->_type = ComplexUnionEnum::_EMPTY_;
    $xfer += $input->readStructBegin($fname);
    while (true)
    {
      $xfer += $input->readFieldBegin($fname, $ftype, $fid);
      if ($ftype == TType::STOP) {
        break;
      }
      if (!$fid && $fname !== null) {
        $fid = (int) self::$_TFIELDMAP->get($fname);
        if ($fid !== 0) {
          $ftype = self::$_TSPEC[$fid]['type'];
        }
      }
      switch ($fid)
      {
        case 1:
          if ($ftype == TType::I64) {
            $xfer += $input->readI64($this->intValue);
            $this->_type = ComplexUnionEnum::intValue;
          } else {
            $xfer += $input->skip($ftype);
          }
          break;
        case 2:
          if ($ftype == TType::STRING) {
            $xfer += $input->readString($this->stringValue);
            $this->_type = ComplexUnionEnum::stringValue;
          } else {
            $xfer += $input->skip($ftype);
          }
          break;
        case 3:
          if ($ftype == TType::LST) {
            $_size1 = 0;
            $_val0 = Vector {};
            $_etype4 = 0;
            $xfer += $input->readListBegin($_etype4, $_size1);
            for ($_i5 = 0; $_size1 === null || $_i5 < $_size1; ++$_i5)
            {
              if ($_size1 === null && !$input->readListHasNext()) {
                break;
              }
              $elem6 = null;
              $xfer += $input->readI64($elem6);
              if ($elem6 !== null) {
                $_val0 []= $elem6;
              }
            }
            $xfer += $input->readListEnd();
            $this->intListValue = $_val0;
            $this->_type = ComplexUnionEnum::intListValue;
          } else {
            $xfer += $input->skip($ftype);
          }
          break;
        case 4:
          if ($ftype == TType::LST) {
            $_size8 = 0;
            $_val7 = Vector {};
            $_etype11 = 0;
            $xfer += $input->readListBegin($_etype11, $_size8);
            for ($_i12 = 0; $_size8 === null || $_i12 < $_size8; ++$_i12)
            {
              if ($_size8 === null && !$input->readListHasNext()) {
                break;
              }
              $elem13 = null;
              $xfer += $input->readString($elem13);
              if ($elem13 !== null) {
                $_val7 []= $elem13;
              }
            }
            $xfer += $input->readListEnd();
            $this->stringListValue = $_val7;
            $this->_type = ComplexUnionEnum::stringListValue;
          } else {
            $xfer += $input->skip($ftype);
          }
          break;
        case 5:
          if ($ftype == TType::STRING) {
            $xfer += $input->readString($this->stringRef);
            $this->_type = ComplexUnionEnum::stringRef;
          } else {
            $xfer += $input->skip($ftype);
          }
          break;
        default:
          $xfer += $input->skip($ftype);
          break;
      }
      $xfer += $input->readFieldEnd();
    }
    $xfer += $input->readStructEnd();
    return $xfer;
  }

  public function write(TProtocol $output): int {
    $xfer = 0;
    $xfer += $output->writeStructBegin('ComplexUnion');
    if ($this->intValue !== null) {
      $_val0 = $this->intValue;
      $xfer += $output->writeFieldBegin('intValue', TType::I64, 1);
      $xfer += $output->writeI64($_val0);
      $xfer += $output->writeFieldEnd();
    }
    if ($this->stringValue !== null) {
      $_val1 = $this->stringValue;
      $xfer += $output->writeFieldBegin('stringValue', TType::STRING, 2);
      $xfer += $output->writeString($_val1);
      $xfer += $output->writeFieldEnd();
    }
    if ($this->intListValue !== null) {
      $_val2 = $this->intListValue;
      if (!($_val2 instanceof Indexish) && !(($_val2 instanceof Iterator || $_val2 instanceof IteratorAggregate) && $_val2 instanceof Countable)) {
        throw new TProtocolException('Bad type in structure.', TProtocolException::INVALID_DATA);
      }
      $xfer += $output->writeFieldBegin('intListValue', TType::LST, 3);
      $output->writeListBegin(TType::I64, count($_val2));
      if ($_val2 !== null)
      {
        foreach ($_val2 as $iter3)
        {
          $xfer += $output->writeI64($iter3);
        }
      }
      $output->writeListEnd();
      $xfer += $output->writeFieldEnd();
    }
    if ($this->stringListValue !== null) {
      $_val4 = $this->stringListValue;
      if (!($_val4 instanceof Indexish) && !(($_val4 instanceof Iterator || $_val4 instanceof IteratorAggregate) && $_val4 instanceof Countable)) {
        throw new TProtocolException('Bad type in structure.', TProtocolException::INVALID_DATA);
      }
      $xfer += $output->writeFieldBegin('stringListValue', TType::LST, 4);
      $output->writeListBegin(TType::STRING, count($_val4));
      if ($_val4 !== null)
      {
        foreach ($_val4 as $iter5)
        {
          $xfer += $output->writeString($iter5);
        }
      }
      $output->writeListEnd();
      $xfer += $output->writeFieldEnd();
    }
    if ($this->stringRef !== null) {
      $_val6 = $this->stringRef;
      $xfer += $output->writeFieldBegin('stringRef', TType::STRING, 5);
      $xfer += $output->writeString($_val6);
      $xfer += $output->writeFieldEnd();
    }
    $xfer += $output->writeFieldStop();
    $xfer += $output->writeStructEnd();
    return $xfer;
  }

}

