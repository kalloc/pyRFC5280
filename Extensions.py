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


####################################################################
'''
   PolicyQualifierInfo ::= SEQUENCE {
        policyQualifierId  PolicyQualifierId,
        qualifier          ANY DEFINED BY policyQualifierId }

   -- policyQualifierIds for Internet policy qualifiers

   id-qt          OBJECT IDENTIFIER ::=  { id-pkix 2 }
   id-qt-cps      OBJECT IDENTIFIER ::=  { id-qt 1 }
   id-qt-unotice  OBJECT IDENTIFIER ::=  { id-qt 2 }
'''
class PolicyQualifierInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('PolicyQualifierId', PolicyQualifierId()),
        namedtype.NamedType('qualifier', univ.Any())
    )
####################################################################
'''
   PolicyInformation ::= SEQUENCE {
        policyIdentifier   CertPolicyId,
        policyQualifiers   SEQUENCE SIZE (1..MAX) OF
                                PolicyQualifierInfo OPTIONAL }
'''
class PolicyQualifiers(univ.SequenceOf):
    componentType = PolicyQualifierInfo()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200)
class PolicyInformation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('policyIdentifier', CertPolicyId()),
        namedtype.OptionalNamedType('policyQualifiers', PolicyQualifiers())
    )


####################################################################
'''
 certificatePolicies ::= SEQUENCE SIZE (1..MAX) OF PolicyInformation
'''
class certificatePolicies(univ.SequenceOf):
    componentType = PolicyInformation()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 
####################################################################
'''
   NoticeReference ::= SEQUENCE {
        organization     DisplayText,
        noticeNumbers    SEQUENCE OF INTEGER }
'''
class NoticeNumbers(univ.SequenceOf):
    componentType = univ.Integer()
class NoticeReference(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('organization', DisplayText()),
        namedtype.NamedType('noticeNumbers', NoticeNumbers())
    )
'''
   UserNotice ::= SEQUENCE {
        noticeRef        NoticeReference OPTIONAL,
        explicitText     DisplayText OPTIONAL }
'''
class UserNotice(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('noticeRef', NoticeReference()),
        namedtype.OptionalNamedType('explicitText', DisplayText())
    )

'''
   Qualifier ::= CHOICE {
        cPSuri           CPSuri,
        userNotice       UserNotice }
'''
class Qualifier(univ.Choice):    
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cPSuri', CPSuri()),
        namedtype.NamedType('userNotice', UserNotice()),
    )
####################################################################
'''
    ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
    KeyPurposeId ::= OBJECT IDENTIFIER
'''
class extKeyUsage(univ.SequenceOf):
    componentType = ObjectIdentifier()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 
    def prettyPrint(self):
        return ', '.join(map(str, map(self.getComponentByPosition, xrange(len(self)))))

####################################################################
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

####################################################################
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

####################################################################
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

####################################################################
class AuthorityKeyIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType('keyIdentifier', univ.OctetString().subtype(
                implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))
            ),
            namedtype.OptionalNamedType('authorityCertIssuer', GeneralNames().subtype(
                implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))
            ),
            namedtype.OptionalNamedType('authorityCertSerialNumber', univ.Integer().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))
            )
    )

####################################################################
'''
 NameConstraints ::= SEQUENCE {
           permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
           excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }

      GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
      GeneralSubtree ::= SEQUENCE {
           base                    GeneralName,
           minimum         [0]     BaseDistance DEFAULT 0,
           maximum         [1]     BaseDistance OPTIONAL }

      BaseDistance ::= INTEGER (0..MAX)
'''

class BaseDistance(univ.Integer):
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(0, 200)

class GeneralSubtree(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('base', GeneralName()),
        namedtype.DefaultedNamedType('minimum', BaseDistance((0)).subtype(
                implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.OptionalNamedType('maximum', BaseDistance().subtype(
                implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
    )


class GeneralSubtrees(univ.SequenceOf):
    componentType = GeneralSubtree()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 

class NameConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('permittedSubtrees', GeneralSubtrees().subtype(
                implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.OptionalNamedType('excludedSubtrees', GeneralSubtrees().subtype(
                implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
    )

####################################################################
'''
   PolicyConstraints ::= SEQUENCE {
        requireExplicitPolicy           [0] SkipCerts OPTIONAL,
        inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
'''

class PolicyConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('requireExplicitPolicy', SkipCerts().subtype(
                implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.OptionalNamedType('inhibitPolicyMapping', SkipCerts().subtype(
                implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
    )

####################################################################
'''
  ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
'''
class ExtKeyUsageSyntax(univ.SequenceOf):
    componentType = ObjectIdentifier()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 

####################################################################
'''
CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint

   DistributionPoint ::= SEQUENCE {
        distributionPoint       [0]     DistributionPointName OPTIONAL,
        reasons                 [1]     ReasonFlags OPTIONAL,
        cRLIssuer               [2]     GeneralNames OPTIONAL }

   DistributionPointName ::= CHOICE {
        fullName                [0]     GeneralNames,
        nameRelativeToCRLIssuer [1]     RelativeDistinguishedName }

   ReasonFlags ::= BIT STRING {
        unused                  (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
        privilegeWithdrawn      (7),
        aACompromise            (8) }

'''
class ReasonFlags(univ.BitString):
    namedValues = namedval.NamedValues(
            ('unused', 0),
            ('keyCompromise', 1),
            ('cACompromise', 2),
            ('affiliationChanged', 3),
            ('superseded', 4),
            ('cessationOfOperation', 5),
            ('certificateHold', 6),
            ('privilegeWithdrawn', 7),
            ('aACompromise', 8)
    )

class DistributionPointName(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('fullName', GeneralNames().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x0))),
        namedtype.NamedType('nameRelativeToCRLIssuer', RelativeDistinguishedName().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0x1))),
    )


class DistributionPoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('distributionPoint', DistributionPointName().subtype(
            implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)
        )),
        namedtype.OptionalNamedType('reasons', ReasonFlags().subtype(
            implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)
        )),
        namedtype.OptionalNamedType('cRLIssuer', GeneralNames().subtype(
            implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)
        )),
    )

class CRLDistributionPoints(univ.SequenceOf):
    componentType = DistributionPoint()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 


####################################################################
'''
 InhibitAnyPolicy ::= SkipCerts
'''
class InhibitAnyPolicy(SkipCerts): pass

####################################################################
'''
   FreshestCRL ::= CRLDistributionPoints
'''
class FreshestCRL(CRLDistributionPoints): pass
####################################################################
'''
  AuthorityInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription

   AccessDescription  ::=  SEQUENCE {
           accessMethod          OBJECT IDENTIFIER,
           accessLocation        GeneralName  }
'''
class AccessDescription(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', ObjectIdentifier()),
        namedtype.NamedType('accessLocation', GeneralName())
    )

class AuthorityInfoAccessSyntax(univ.SequenceOf):
    componentType = AccessDescription()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 

####################################################################
'''
 SubjectInfoAccessSyntax  ::=
           SEQUENCE SIZE (1..MAX) OF AccessDescription
'''
class SubjectInfoAccessSyntax(univ.SequenceOf):
    componentType = AccessDescription()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 

####################################################################
'''

   CertificateList  ::=  SEQUENCE  {
        tbsCertList          TBSCertList,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING  }

   TBSCertList  ::=  SEQUENCE  {
        version                 Version OPTIONAL,
                                     -- if present, MUST be v2
        signature               AlgorithmIdentifier,
        issuer                  Name,
        thisUpdate              Time,
        nextUpdate              Time OPTIONAL,
        revokedCertificates     SEQUENCE OF SEQUENCE  {
             userCertificate         CertificateSerialNumber,
             revocationDate          Time,
             crlEntryExtensions      Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }  OPTIONAL,
        crlExtensions           [0]  EXPLICIT Extensions OPTIONAL
                                      -- if present, version MUST be v2
                                  }

'''

class RevokedCertificate(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('userCertificate', CertificateSerialNumber()),
        namedtype.NamedType('revocationDate', Time()),
        namedtype.OptionalNamedType('crlEntryExtensions', Extensions())
    )

class RevokedCertificates(univ.SequenceOf):
    componentType = RevokedCertificate()

class TBSCertList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('version', Version()),
        namedtype.NamedType('signature', AlgorithmIdentifier()),
        namedtype.NamedType('issuer', Name()),
        namedtype.NamedType('thisUpdate', Time()),
        namedtype.OptionalNamedType('nextUpdate', Time()),
        namedtype.OptionalNamedType('revokedCertificates', RevokedCertificates()),
        namedtype.OptionalNamedType('crlEntryExtensions',Extensions().subtype(
            explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0x0))
        ),
    )


class CertificateList(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tbsCertList', TBSCertList()),
        namedtype.NamedType('signatureAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('signatureValue', univ.BitString()),
    )

class AuthorityInfoAccessSyntax(univ.SequenceOf):
    componentType = AccessDescription()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 


####################################################################
'''
   IssuingDistributionPoint ::= SEQUENCE {
        distributionPoint          [0] DistributionPointName OPTIONAL,
        onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
        onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
        onlySomeReasons            [3] ReasonFlags OPTIONAL,
        indirectCRL                [4] BOOLEAN DEFAULT FALSE,
        onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE }


   CRLReason ::= ENUMERATED {
        unspecified             (0),
        keyCompromise           (1),
        cACompromise            (2),
        affiliationChanged      (3),
        superseded              (4),
        cessationOfOperation    (5),
        certificateHold         (6),
             -- value 7 is not used
        removeFromCRL           (8),
        privilegeWithdrawn      (9),
        aACompromise           (10) }
'''
class CRLReason(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('unspecified', 0),
        ('keyCompromise', 1),
        ('cACompromise', 2),
        ('affiliationChanged', 3),
        ('superseded', 4),
        ('cessationOfOperation', 5),
        ('certificateHold', 6),
        ('removeFromCRL', 8),
        ('privilegeWithdrawn', 9),
        ('aACompromise', 10),
    )
    subtypeSpec = univ.Enumerated.subtypeSpec + \
                    constraint.SingleValueConstraint(0, 1, 2, 3, 4, 5, 6, 8, 9, 10)
class IssuingDistributionPoint(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('distributionPoint', DistributionPointName()),
        namedtype.DefaultedNamedType('onlyContainsUserCerts', univ.Boolean(False)),
        namedtype.DefaultedNamedType('onlyContainsCACerts', univ.Boolean(False)),
        namedtype.OptionalNamedType('onlySomeReasons', ReasonFlags()),
        namedtype.DefaultedNamedType('indirectCRL', univ.Boolean(False)),
        namedtype.DefaultedNamedType('onlyContainsAttributeCerts', univ.Boolean(False))
    )

####################################################################
'''
 PolicyMappings ::= SEQUENCE SIZE (1..MAX) OF SEQUENCE {
    issuerDomainPolicy      CertPolicyId,
    subjectDomainPolicy     CertPolicyId }
'''
class PolicyMapping(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuerDomainPolicy', CertPolicyId()),
        namedtype.NamedType('subjectDomainPolicy', CertPolicyId())
    )

class PolicyMappings(univ.SequenceOf):
    componentType = PolicyMapping()
    subtypeSpec = univ.SequenceOf.subtypeSpec + constraint.ValueSizeConstraint(1, 200) 



####################################################################
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

####################################################################
class AuthorityKeyIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType('keyIdentifier', univ.OctetString().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.OptionalNamedType('authorityCertIssuer', GeneralNames().subtype(implicitTag = tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
            namedtype.OptionalNamedType('authorityCertSerialNumber', univ.Integer().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
    )
