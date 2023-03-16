import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.Attributes;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.tsp.cms.CMSTimeStampedDataGenerator;
import org.bouncycastle.util.Store;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

public class TimeStampAuthority {
    protected final static String timeStampAlias="Kronos";
    protected final static char[] timeStampPassword="TimeManagement100".toCharArray();
    protected static TimeStampToken generateTimeStamp(byte[] inputToSign) throws KeyStoreException, UnrecoverableKeyException,
            NoSuchAlgorithmException, OperatorCreationException, CertificateEncodingException, IOException, TSPException, CMSException {
        Certificate[] certChain2 = RootInitializer.getKeyStore().getCertificateChain(timeStampAlias);
        X509Certificate[] certChain = new X509Certificate[certChain2.length];
        for (int i = 0; i < certChain2.length; i++) {
            certChain[i] = (X509Certificate) certChain2[i];
        }
        X509Certificate timestampServiceCert = certChain[0];
        PrivateKey pk = (PrivateKey) RootInitializer.getKeyStore().getKey(timeStampAlias, timeStampPassword);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(pk);
        ASN1ObjectIdentifier algOID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");

        JcaSignerInfoGeneratorBuilder infoGeneratorBuilder = new JcaSignerInfoGeneratorBuilder(
                new JcaDigestCalculatorProviderBuilder().build());

        DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator hashCalculator = digestProvider.get(new AlgorithmIdentifier(algOID));

        CMSTimeStampedDataGenerator cmsTimeStampedDataGenerator = new CMSTimeStampedDataGenerator();

        cmsTimeStampedDataGenerator.initialiseMessageImprintDigestCalculator(hashCalculator);

        hashCalculator.getOutputStream().write(inputToSign);
        hashCalculator.getOutputStream().close();

        TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(infoGeneratorBuilder.build(
                new JcaContentSignerBuilder("SHA256withRSA").build(pk), timestampServiceCert),
                hashCalculator, new ASN1ObjectIdentifier("1.2.840.113549.1.9.16.1.4"));
        tsTokenGen.addCertificates(new JcaCertStore(Arrays.asList(certChain)));
        byte[] requestData = hashCalculator.getDigest();

        //tsTokenGen.setAccuracySeconds(1);
        tsTokenGen.setLocale(new Locale("fr","MA"));
        //tsTokenGen.setTSA(new GeneralName(GeneralName.uniformResourceIdentifier, ));

        List certList = Arrays.asList(certChain);
        Store certs = new JcaCertStore(certList);
        //tsTokenGen.addCRLs(new JcaCertStore(Collections.singletonList(new JcaX509CRLConverter().getCRL(getCRLHolder()))));
        tsTokenGen.addCertificates(certs);
        tsTokenGen.addAttributeCertificates(certs);

        TimeStampRequestGenerator reqGen = new TimeStampRequestGenerator();
        TimeStampRequest request = reqGen.generate(algOID, requestData);

        TimeStampResponseGenerator tsRespGen = new TimeStampResponseGenerator(tsTokenGen, TSPAlgorithms.ALLOWED);
        TimeStampResponse tsResp = tsRespGen.generate(request, new BigInteger("23"), new Date());
        return tsResp.getTimeStampToken();
    }
    private static CMSSignedData signTimeStamps(CMSSignedData signedData)
            throws IOException, TSPException {
        SignerInformationStore signerStore = signedData.getSignerInfos();
        List<SignerInformation> newSigners = new ArrayList<>();

        for (SignerInformation signer : signerStore.getSigners())
        {
            newSigners.add(signTimeStamp(signer));
        }

        // TODO do we have to return a new store?
        return CMSSignedData.replaceSigners(signedData, new SignerInformationStore(newSigners));
    }
    private static SignerInformation signTimeStamp(SignerInformation signer)
            throws IOException, TSPException
    {
        AttributeTable unsignedAttributes = signer.getUnsignedAttributes();

        ASN1EncodableVector vector = new ASN1EncodableVector();
        if (unsignedAttributes != null)
        {
            vector = unsignedAttributes.toASN1EncodableVector();
        }

        byte[] token = new byte[0];
        try {
            TimeStampToken toooken = TimeStampAuthority.generateTimeStamp(signer.getSignature());
            System.out.println(convertToJSON(toooken));
            token = toooken.getEncoded();
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (CMSException e) {
            throw new RuntimeException(e);
        }
        ASN1ObjectIdentifier oid = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken;
        ASN1Encodable signatureTimeStamp = new Attribute(oid, new DERSet(ASN1Primitive.fromByteArray(token)));

        vector.add(signatureTimeStamp);
        Attributes signedAttributes = new Attributes(vector);

        SignerInformation newSigner = SignerInformation.replaceUnsignedAttributes(
                signer, new AttributeTable(signedAttributes));

        // TODO can this actually happen?
        if (newSigner == null)
        {
            System.out.println("new Signer is null");
            return signer;
        }

        return newSigner;
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
}
