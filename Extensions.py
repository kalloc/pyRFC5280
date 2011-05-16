# -*- coding:utf-8 -*-
#
from pyasn1.type import univ, namedtype, tag, namedval, char, constraint
from Types import *
from oid import OID




def getExtensionClassbyOID(oid):
    oid = str(oid)
    try:
        module = __import__('Extensions', globals(), locals(), [oid])
        return vars(module)[oid]
    except:
        return None


class extKeyUsage(univ.SequenceOf):
    componentType = ObjectIdentifier()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 
    def prettyPrint(self):
        return ', '.join(map(str, map(self.getComponentByPosition, xrange(len(self)))))

class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extnID', ObjectIdentifier()),
        namedtype.DefaultedNamedType('critical', univ.Boolean('False')),
        namedtype.NamedType('extnValue', univ.OctetString())
        )


class basicConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.DefaultedNamedType('CA', univ.Boolean(False)),
            namedtype.OptionalNamedType('pathLenConstraint', univ.Integer())
    )
    def prettyPrint(self):
        if self.getComponentByName('CA') == False:
            out = 'CA:FALSE'
        else:
            out = 'CA:TRUE'
        pathLen = self.getComponentByName('pathLenConstraint')
        if pathLen:
            out = out+', %d' % (int(pathLen),)
        return out 

class  nsCertType(univ.BitString):
    namedValues = namedval.NamedValues(
            ('client', 0),
            ('server', 1),
            ('email', 2),
            ('objsign', 3),
            ('reserved', 4),
            ('sslCA', 5),
            ('emailCA', 6),
            ('objCA', 7)
    )
    def prettyPrint(self):
        textName = map(lambda (id, active): active and self.namedValues[id][0] or None, enumerate(self._value))
        return ', '.join(filter(lambda x: x, textName))

class  keyUsage(univ.BitString):
    namedValues = namedval.NamedValues(
            ('digitalSignature', 0),
            ('nonRepudiation', 1),
            ('keyEncipherment', 2),
            ('dataEncipherment', 3),
            ('keyAgreement', 4),
            ('keyCertSign', 5),
            ('cRLSign', 6),
            ('encipherOnly', 7),
            ('decipherOnly', 8)
    )
    def prettyPrint(self):
        textName = map(lambda (id, active): active and self.namedValues[id][0] or None, enumerate(self._value))
        return ', '.join(filter(lambda x: x, textName))


class Extensions(univ.SequenceOf):
    componentType = Extension()
    sizeSpec = univ.SequenceOf.sizeSpec

class AuthorityKeyIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType('keyIdentifier', univ.OctetString().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.OptionalNamedType('authorityCertIssuer', GeneralNames().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
            namedtype.OptionalNamedType('authorityCertSerialNumber', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
    )

