# -*- coding:utf-8 -*-
#

from pyasn1.type import univ, namedtype, tag, namedval, char, constraint, useful
from pyasn1 import error
from oid import OID

def toHex(value, new_lines = True, input_is_integer = True):
        res = []
        if input_is_integer:
            hex = '%X' % value
            if len(hex)%2:
                hex = '0' + hex
            value = hex.decode('hex')
        for n in xrange(0, len(value)/18 + (len(value)%18 and 1 or 0)):
            res.append(':'.join (map(lambda hex: '%02X' % ord(hex), value[n*18:(n+1)*18])))
        delim = "\n" if new_lines else ""
        return delim.join(res)

class Integer(univ.Integer):
    def __len__(self):
        n = self._value 
        l = 0
        while n > 0:
            n = n >> 8 
            l+=1
        return l
    def toHex(self, new_lines = True):
        return toHex(self._value, new_lines)

class Time(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utcTime', useful.UTCTime()),
        namedtype.NamedType('generalTime', useful.GeneralizedTime())
        )
    def __str__(self):
        return str(self.getComponent())
    
class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', Time()),
        namedtype.NamedType('notAfter', Time())
        )



class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('v1', 0), ('v2', 1), ('v3', 2)
        )

'''
   SkipCerts ::= INTEGER (0..MAX)
'''
class SkipCerts(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, 200)
'''
   DisplayText ::= CHOICE {
        ia5String        IA5String      (SIZE (1..200)),
        visibleString    VisibleString  (SIZE (1..200)),
        bmpString        BMPString      (SIZE (1..200)),
        utf8String       UTF8String     (SIZE (1..200)) }
'''
class DisplayText(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ia5String', char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
        namedtype.NamedType('visibleString', char.VisibleString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
        namedtype.NamedType('bmpString', char.BMPString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x2))),
        namedtype.NamedType('utf8String', char.UTF8String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x3))),
    )
class ConvertibleBitString(univ.BitString):
    def prettyPrint(self, scope = 0):
        return self.toPrint()

    def __str__(self):
        return self.toPrint()

    def __len__(self):
        return len(self._value)

    def toPrint(self, new_lines = True):
        return toHex(int(''.join(map(str, self._value)), 2), new_lines)

class DirectoryString(univ.Choice):    
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString', char.TeletexString()),
        namedtype.NamedType('printableString', char.PrintableString()),
        namedtype.NamedType('universalString', char.UniversalString()),
        namedtype.NamedType('utf8String', char.UTF8String()),
        namedtype.NamedType('bmpString', char.BMPString()),
        namedtype.NamedType('ia5String', char.IA5String()),
        namedtype.NamedType('gString', univ.OctetString())
    )
    def __str__(self):
        return str(self.getComponentByPosition(self._currentIdx)).decode('utf-8', 'ignore')

    def __repr__(self):
        return self.__str__()

class ObjectIdentifier(univ.ObjectIdentifier):
    def toPrint(self):
        value = '.'.join(map(str, self._value))
        (name, title) = OID.get(value, (value, ''))
        return name
    def __str__(self):
        return self.toPrint()

class PolicyQualifierId(ObjectIdentifier): pass
class CertPolicyId(ObjectIdentifier): pass
class AttributeValue(DirectoryString): pass
class AttributeType(ObjectIdentifier):  pass
class CPSuri(char.IA5String): pass
class CertificateSerialNumber(univ.Integer): pass
class CRLNumber(univ.Integer): pass
class BaseCRLNumber(CRLNumber): pass
class InvalidityDate(useful.GeneralizedTime): pass


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeType()),
        namedtype.NamedType('value', AttributeValue())
    )

class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('', RDNSequence())
    )


class AlgorithmIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any())
    )

class UniqueIdentifier(ConvertibleBitString):
    def prettyPrint(self, scope = 0):
        return self.__str__()
    def __str__(self):
        print 'UniqueIdentifier', self.value
        return self.toPrint(False)

    def __repr__(self):
        return self.__str__()

class DirectoryName(univ.Choice):    
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString', char.TeletexString()),
        namedtype.NamedType('printableString', char.PrintableString()),
        namedtype.NamedType('universalString', char.UniversalString()),
        namedtype.NamedType('utf8String', char.UTF8String()),
        namedtype.NamedType('bmpString', char.BMPString()),
    )

class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

    def __str__(self):
        buf = ''
        for component in self._componentValues:
            buf += str(component)
            buf += ','
        buf = buf[:len(buf)-1]
        return buf

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

    def __str__(self):
        buf = ''        
        for component in self._componentValues:            
            buf += str(component)
            buf += ','
        buf = buf[:len(buf)-1]
        return buf


class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('', RDNSequence())
    )

    def __str__(self):
        return str(self.getComponent())

class DirectoryString(univ.Choice):    
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('teletexString', char.TeletexString()),
        namedtype.NamedType('printableString', char.PrintableString()),
        namedtype.NamedType('universalString', char.UniversalString()),
        namedtype.NamedType('utf8String', char.UTF8String()),
        namedtype.NamedType('bmpString', char.BMPString()),
        namedtype.NamedType('ia5String', char.IA5String()),
        namedtype.NamedType('gString', univ.OctetString())
        )
    def __repr__(self):
        try:
          c = self.getComponent()
          return c.__str__()
        except:
          return "Choice type not chosen"
    def __str__(self):
        return repr(self)


class AttributeValue(DirectoryString): pass


class AttributeType(univ.ObjectIdentifier): 
    def __str__(self):
        return tuple_to_OID(self._value)

class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('type', AttributeType()),
            namedtype.NamedType('value', AttributeValue())
            )
    def __repr__(self):
        # s = "%s => %s" % [ self.getComponentByName('type'), self.getComponentByName('value')]
        type = self.getComponentByName('type')
        value = self.getComponentByName('value')
        s = "%s => %s" % (type,value)
        return s

    def __str__(self):
        return self.__repr__()


class AttributeTypeAndValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('type', AttributeType()),
            namedtype.NamedType('value', AttributeValue())
    )

class RelativeDistinguishedName(univ.SetOf):
    componentType = AttributeTypeAndValue()

class RDNSequence(univ.SequenceOf):
    componentType = RelativeDistinguishedName()

class Name(univ.Choice):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('', RDNSequence())
    )


class SubjectPublicKeyInfo(univ.Sequence):
     componentType = namedtype.NamedTypes(
         namedtype.NamedType('algorithm', AlgorithmIdentifier()),
         namedtype.NamedType('subjectPublicKey', ConvertibleBitString())
         )


class signatureAlgorithm(univ.Sequence):
    componentType = namedtype.NamedTypes(
                namedtype.NamedType('algorithm', ObjectIdentifier()),
                namedtype.OptionalNamedType('parameters', univ.Any())
            )
class GeneralName(univ.Choice):

    componentType = namedtype.NamedTypes(
        namedtype.NamedType('otherName', univ.Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
        namedtype.NamedType('rfc822Name', char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
        namedtype.NamedType('dNSName', char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x2))),
        namedtype.NamedType('x400Address', univ.Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x3))),
        namedtype.NamedType('directoryName', Name().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x4))),
        namedtype.NamedType('ediPartyName', univ.Sequence().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x5))),
        namedtype.NamedType('uniformResourceIdentifier', char.IA5String().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x6))),
        namedtype.NamedType('iPAddress', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x7))),
        namedtype.NamedType('registeredID', ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x8))),
        )

class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 

class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString())
        )

class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec

class CertificateIssuer(GeneralNames): pass
'''
  GostR3410-2001-PublicKeyParameters ::=
        SEQUENCE {
            publicKeyParamSet
                OBJECT IDENTIFIER,
            digestParamSet
                OBJECT IDENTIFIER,
            encryptionParamSet
                OBJECT IDENTIFIER DEFAULT
                    id-Gost28147-89-CryptoPro-A-ParamSet
        }

'''
class GostR3410_2001_PublicKeyParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('publicKeyParamSet', ObjectIdentifier()),
            namedtype.NamedType('digestParamSet', ObjectIdentifier()),
            namedtype.DefaultedNamedType('encryptionParamSet', ObjectIdentifier('1.2.643.2.2.31.1'))
    )

'''
GostR3410-94-PublicKey ::= OCTET STRING
'''
class GostR3410_94_PublicKey(univ.OctetString): 
    def prettyPrint(self, scope = 0):
        return self.toPrint()

    def __str__(self):
        return self.toPrint()

    def __len__(self):
        return len(self._value)
    def toPrint(self, new_lines = True):
        return toHex(self._value, input_is_integer = False, new_lines = new_lines)


'''
RSAPublicKey::=SEQUENCE{
     modulus INTEGER, -- n
     publicExponent INTEGER -- e }
'''

class RSAPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('modulus', Integer()),
        namedtype.NamedType('publicExponent', Integer())
    )

    def getModulus(self):
        return self.getComponentByName('modulus')

    def toPrint(self, new_lines = True):
        public = int(self.getComponentByName('publicExponent'), 2)
        return toHex(value,  new_lines)

    def __len__(self):
        public = self.getComponentByName('publicExponent')
        hex = '%X' % public 
        if len(hex)%2:
            hex = '0' + hex
        raw = hex.decode('hex')
        return len(raw)

