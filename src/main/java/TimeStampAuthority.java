import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.ess.SigningCertificateV2;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataGenerator;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class TimeStampAuthority {

    private final ASN1ObjectIdentifier algOID;
    private final CertificateChainAndPrivateKey timeStampAuthorityCert;
    private final String hashAndCryptAlg;
    private final String policyOid;

    //private SigningCertificateV2 signingCertAttr;

    private final TimeStampResponseGenerator timeStampResponseGenerator;
    private DigestCalculator hashCalculator;

    public TimeStampAuthority(CertificateChainAndPrivateKey tsaCert, String hashAndCryptAlg, ASN1ObjectIdentifier algOID, String policyOid) {
        this.timeStampAuthorityCert=tsaCert;
        this.algOID=algOID;
        this.hashAndCryptAlg=hashAndCryptAlg;
        this.policyOid=policyOid;
        //this.signingCertAttr=initSigningCertificate();
        try {
            //CHECK ALG NAME
            SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
                    .build(hashAndCryptAlg, tsaCert.getPk(), tsaCert.getMyCert());

            DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();
            hashCalculator = digestProvider.get(new AlgorithmIdentifier(algOID));

            //CMSTimeStampedDataGenerator cmsTimeStampedDataGenerator = new CMSTimeStampedDataGenerator();
            //cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);

            TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(signerInfoGenerator,
                    hashCalculator, new ASN1ObjectIdentifier(policyOid));
            /*tsTokenGen.addCertificates(new CollectionStore<>(List.of(new X509CertificateHolder(
                    timeStampAuthorityCert.getMyCert().getEncoded()))));*/



            //tsTokenGen.addCertificates(new JcaCertStore(Arrays.asList(this.timeStampAuthorityCert.getMyCertChain())));
            //tsTokenGen.setAccuracySeconds(1);
            tsTokenGen.setLocale(new Locale("fr","MA"));
            //tsTokenGen.setTSA(new GeneralName(GeneralName.uniformResourceIdentifier, ));
            //tsTokenGen.addCRLs(new JcaCertStore(Collections.singletonList(new JcaX509CRLConverter().getCRL(getCRLHolder()))));
            //tsTokenGen.addCertificates(certs);
            //tsTokenGen.addAttributeCertificates(certs);

            /*ArrayList<X509CertificateHolder> certHL=new ArrayList<>();
            for(X509Certificate certToInsert : certChain){
                certHL.add(new X509CertificateHolder(certToInsert.getEncoded()));
            }
            tsTokenGen.addCertificates(new CollectionStore<>(certHL));*/

            this.timeStampResponseGenerator = new TimeStampResponseGenerator(tsTokenGen,
                    Set.of(algOID), TSPAlgorithms.ALLOWED);//no alg oid ?
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected CMSSignedData signTimeStamps(CMSSignedData signedData)
            throws IOException, TSPException {
        SignerInformationStore signerStore = signedData.getSignerInfos();
        List<SignerInformation> newSigners = new ArrayList<>();

        for (SignerInformation signer : signerStore.getSigners())
        {
            signerStore= new SignerInformationStore(signTimeStamp(signer));
        }

        // TODO do we have to return a new store?
        return CMSSignedData.replaceSigners(signedData, signerStore);
    }
    private SignerInformation signTimeStamp(SignerInformation signer)
            throws IOException, TSPException
    {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (unsignedAttributes != null)
        {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        //TimeStampToken toooken = TimeStampAuthority.generateTimeStamp(signer.getSignature());
        //System.out.println(convertToJSON(toooken));
        //Attribute tokenAttr = TimeStampAuthority.createTSTokenAttribute(signer.getSignature());
        byte[] token = sendRequest(signer.getSignature()).getTimeStampToken().getEncoded();
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
        ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

        vector.add(signatureTimeStamp);
        Attributes signedAttributes = new Attributes(vector);

        SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(
                signer, new AttributeTable(vector));

        // TODO can this actually happen?
        if (newSigner == null)
        {
            System.out.println("new Signer is null");
            return signer;
        }

        return newSigner;
    }


    public TimeStampResponse sendRequest(byte[] dataToStamp){
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        //reqGen.setCertReq(true);
        TimeStampRequest request = reqGen.generate(algOID, hash(dataToStamp));
        return generateTSResponse(request);
    }
    private byte[] hash(byte[] inputToHash){
        byte[] digest;
        try {
            CMSTimeStampedDataGenerator cmsTimeStampedDataGenerator = new CMSTimeStampedDataGenerator();
            cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);
            hashCalculator.getOutputStream().write(inputToHash);
            digest = hashCalculator.getDigest();
            hashCalculator.getOutputStream().flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CMSException e) {
            throw new RuntimeException(e);
        }
        return digest;
    }

    private TimeStampResponse generateTSResponse(TimeStampRequest timeStampRequest) {
        BigInteger tspResponseSerial = BigInteger.valueOf(generateTimeStampSerialNumber());
        Date receptionTime = new Date();
        TimeStampResponse tspResponse = null;
        try {
            tspResponse = timeStampResponseGenerator.generate(timeStampRequest, tspResponseSerial,
                    receptionTime);
        } catch (TSPException e) {
            throw new RuntimeException(e);
        }
        return tspResponse;
    }

    //REDO LATER
    private long generateTimeStampSerialNumber (){
        return new java.util.Random().nextLong();
    }

    private SigningCertificateV2 SigningCertificateV2(){
        ESSCertIDv2 eSSCertID = null;
        try {
            eSSCertID = new ESSCertIDv2(new AlgorithmIdentifier(algOID) ,hash(timeStampAuthorityCert.getMyCert().getEncoded()));
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        }

        return new SigningCertificateV2(eSSCertID);
    }
    private SignerInfo getSignerInfo(byte[] hash){
        X509Certificate rootCert = (this.timeStampAuthorityCert.getMyCertChain()[this.timeStampAuthorityCert.getMyCertChain().length-1]);
        IssuerAndSerialNumber issuerAndId= new IssuerAndSerialNumber(
                new X500Name(rootCert.getSubjectX500Principal().getName())
                , timeStampAuthorityCert.getMyCert().getSerialNumber());
        SignerIdentifier sigId;
        sigId = new SignerIdentifier(issuerAndId);
        //sigId = new SignerIdentifier(SubjectPublicKeyInfo.getInstance(this.timeStampAuthorityCert.getMyCert().getPublicKey().getEncoded()).toASN1Primitive());
        //or maybe certChain(length-1)?
        SignerInfo sigInfo = new SignerInfo(sigId, new AlgorithmIdentifier(algOID), new DERSet(), new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption),
                ASN1OctetString.getInstance(hash), new DERSet());
        return sigInfo;
    }

    public static String convertToJSON(TimeStampToken token) {
        try {
            ObjectMapper mapper = new ObjectMapper();
            mapper.enable(SerializationFeature.INDENT_OUTPUT);
            mapper.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
            String json = mapper.writeValueAsString(token);
            return json;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    public boolean isValidTimeStamp(TimeStampToken timeStampToken) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
        ASN1Encodable signatureTimeStamp = null;
        try {
            signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(timeStampToken.getEncoded())));
        } catch (IOException e) {
            return false;
        }
        vector.add(signatureTimeStamp);
        Attributes timeStampAttr = new Attributes(vector);
        if (timeStampAttr == null) {
            return false;
        }
        // Validate the time stamp token's signature using the signer's certificate
        SignerInformationVerifier verifier = null;
        try {
            verifier = new JcaSimpleSignerInfoVerifierBuilder().build(this.timeStampAuthorityCert.getMyCert());
        } catch (OperatorCreationException e) {
            return false;
        }
        try {
            if (!timeStampToken.isSignatureValid(verifier)) {
                return false;
            }
        } catch (TSPException e) {
            return false;
        }
        // Check the time stamp token's time stamp against the current time
        Date currentTime = new Date();
        if (currentTime.before(timeStampToken.getTimeStampInfo().getGenTime())) {
            return false;
        }
        // Verify the time stamp token's certificate chain
        CertStoreParameters params = new CollectionCertStoreParameters(timeStampToken.getCertificates().getMatches(null));
        CertStore store = null;
        try {
            store = CertStore.getInstance("Collection", params);
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            return false;
        }
        List<X509Certificate> certs = new ArrayList<>();
        try {
            for (X509Certificate cert : (Collection<X509Certificate>) store.getCertificates(null)) {
                certs.add(cert);
            }
        } catch (CertStoreException e) {
            return false;
        }
        return true;
    }
}
