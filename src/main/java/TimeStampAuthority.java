import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataGenerator;
import org.bouncycastle.util.CollectionStore;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.*;

public class TimeStampAuthority {

    private final ASN1ObjectIdentifier algOID;
    private final CertificateChainAndPrivateKey timeStampAuthorityCert;
    private final TimeStampResponseGenerator timeStampResponseGenerator;
    private final TimeStampTokenGenerator timeStampTokenGenerator;
    private DigestCalculator hashCalculator;

    public TimeStampAuthority(CertificateChainAndPrivateKey tsaCert, String hashAndCryptAlg, ASN1ObjectIdentifier algOID, String policyOid) {
        this.timeStampAuthorityCert=tsaCert;
        this.algOID=algOID;
        try {
            SignerInfoGenerator signerInfoGenerator = new JcaSimpleSignerInfoGeneratorBuilder()
                    .build(hashAndCryptAlg, tsaCert.getPk(), tsaCert.getMyCert());

            DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();
            hashCalculator = digestProvider.get(new AlgorithmIdentifier(algOID));

            CMSTimeStampedDataGenerator cmsTimeStampedDataGenerator = new CMSTimeStampedDataGenerator();
            cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);

            timeStampTokenGenerator = new TimeStampTokenGenerator(signerInfoGenerator,
                    hashCalculator, new ASN1ObjectIdentifier(policyOid), true);

            timeStampTokenGenerator.addCertificates(new CollectionStore<>(List.of(new X509CertificateHolder(
                    timeStampAuthorityCert.getMyCert().getEncoded()))));

            this.timeStampResponseGenerator = new TimeStampResponseGenerator(timeStampTokenGenerator, TSPAlgorithms.ALLOWED);
                   // Set.of(algOID), TSPAlgorithms.ALLOWED);//no alg oid ?
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    protected CMSSignedData signTimeStamps(CMSSignedData signedData) throws IOException, TSPException {
        SignerInformationStore signerStore = signedData.getSignerInfos();
        for (SignerInformation signer : signerStore.getSigners())
            signerStore= new SignerInformationStore(signTimeStamp(signer));
        // TODO do we have to return a new store?
        return CMSSignedData.replaceSigners(signedData, signerStore);
    }
    private SignerInformation signTimeStamp(SignerInformation signer) throws IOException {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();
        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (unsignedAttributes != null)
            vector = unsignedAttributes.toASN1EncodableVector();
        TimeStampResponse tsr = sendRequest(signer.getSignature());
        TimeStampToken tst=tsr.getTimeStampToken();
        ASN1Encodable signatureTimeStamp = new Attribute(PKCSObjectIdentifiers.id_aa_signatureTimeStampToken, new DERSet(ASN1Primitive.fromByteArray(tst.getEncoded())));
        vector.add(signatureTimeStamp);
        SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(signer, new AttributeTable(vector));
        return newSigner;
    }


    public TimeStampResponse sendRequest(byte[] dataToStamp){
        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        reqGen.setCertReq(true);
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
        BigInteger tspResponseSerial = generateTimeStampSerialNumber();
        Date receptionTime = new Date();
        TimeStampResponse tspResponse = null;
        try {
            tspResponse = timeStampResponseGenerator.generate(timeStampRequest, tspResponseSerial,receptionTime);
        } catch (TSPException e) {
            throw new RuntimeException(e);
        }
        return tspResponse;
    }

    //REDO LATER
    private BigInteger generateTimeStampSerialNumber() {
        return BigInteger.valueOf(new java.util.Random().nextLong());
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
