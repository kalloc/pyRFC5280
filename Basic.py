# -*- coding:utf-8 -*-
#

from pyasn1.type import univ, namedtype, tag, namedval, char, constraint

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
        namedtype.NamedType('registeredID', univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x8))),
        )

class GeneralNames(univ.SequenceOf):
    componentType = GeneralName()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 

class AuthorityKeyIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType('keyIdentifier', univ.OctetString().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.OptionalNamedType('authorityCertIssuer', GeneralNames().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
            namedtype.OptionalNamedType('authorityCertSerialNumber', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
    )
