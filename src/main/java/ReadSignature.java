import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/*import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;
import sun.security.tools.keytool.CertAndKeyGen;*/


public class ReadSignature {
    public static void main(String[] args) {

        //validateDoc("C:\\Users\\Youness\\Downloads\\contract2.pdf");
        validateDoc("C:\\Users\\Youness\\Downloads\\MyPdfTest Signed.pdf");
        //validateDoc("C:\\Users\\Youness\\Downloads\\CV Chetouan Youness 2023 Signed.pdf");
    }
    public static void validateDoc(String path) {
        PDDocument document=null;
        //FileInputStream fis;
        try {
            File signedFile= new File(path);
            //fis = new FileInputStream(f);
            document = PDDocument.load(signedFile);
            System.out.println(" reading "+signedFile.getName()+"\n");
            List<PDSignature> signatures = document.getSignatureDictionaries();
            //List<PDSignature> signatures = SignatureUtils.getSignatures(document);
            for (PDSignature signature : signatures) {
                System.out.println("Signature found");
                System.out.println("Name: " + signature.getName());
                System.out.println("Filter: " + signature.getFilter());
                System.out.println("SubFilter: " + signature.getSubFilter()+"\n");
                //TimeStampToken tst = extractTimeStampToken(signature);
                //TimeStampAuthority.isValidTimeStamp(tst);

                byte[] signatureContent = signature.getContents(new FileInputStream(signedFile));
                byte[] signedContent = signature.getSignedContent(new FileInputStream(signedFile));

                CMSProcessable cmsProcessableInputStream = new CMSProcessableByteArray(signedContent);
                try {
                    CMSSignedData cmsSignedData = new CMSSignedData(cmsProcessableInputStream, signatureContent);
                    // get certificates
                    Store<?> certStore = cmsSignedData.getCertificates();
                    // get signers
                    SignerInformationStore signers = cmsSignedData.getSignerInfos();
                    // variable "it" iterates all signers
                    for (SignerInformation signer : signers.getSigners()) {
                        // get all certificates for a signer
                        Collection<?> certCollection = certStore.getMatches(signer.getSID());
                        // variable "certIt" iterates all certificates of a signer
                        for (Object o : certCollection) {
                            // print details of each certificate
                            X509CertificateHolder certificateHolder = (X509CertificateHolder) o;
                            System.out.println("Subject:\n\t\t\t" + certificateHolder.getSubject().toString()
                                    .replace(",", "\n\t\t\t"));
                            System.out.println("Issuer:\n\t\t\t" + certificateHolder.getIssuer().toString()
                                    .replace(",", "\n\t\t\t"));
                            System.out.println("Valid from:   " + certificateHolder.getNotBefore());
                            System.out.println("Signed at:    " + signature.getSignDate().getTime());
                            System.out.println("Valid to:     " + certificateHolder.getNotAfter());

                            //System.out.println("Public key:   " + Hex.toHexString(certificateHolder.getSubjectPublicKeyInfo().getPublicKeyData().getOctets()));

                            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                            InputStream in = new ByteArrayInputStream(certificateHolder.getEncoded());
                            X509Certificate cert2 = (X509Certificate) certFactory.generateCertificate(in);

                            //System.out.println(Arrays.toString(cert2.getEncoded()));

                            // the validity of the certificate isn't verified, just the fact that one of the certs matches the given signer
                            SignerInformationVerifier signerInformationVerifier = new JcaSimpleSignerInfoVerifierBuilder()
                                    .build(cert2);
                            try {
                                //will fail if :
                                //Data was altered after it was signed
                                //the public key does not match the private key used to sign the signature
                                // the certificate chain is not trusted.
                                if (signer.verify(signerInformationVerifier))
                                    System.out.println("CA is recognised" +
                                            "\npublic key does match the private key used to sign the document" +
                                            "\nData was not altered after signature");
                            } catch (Exception e) {
                                System.out.println("\nPDF SIGNATURE VERIFICATION FAILED\n");
                                e.printStackTrace();
                            }

                            StringBuilder encodedChain = new StringBuilder();
                            encodedChain.append("-----BEGIN CERTIFICATE-----\n");
                            encodedChain.append(new String(Hex.encode(cert2.getEncoded())));
                            encodedChain.append("\n-----END CERTIFICATE-----\n");
                            System.out.println(encodedChain);

                            //System.out.println("Public key:   " + DatatypeConverter.printHexBinary(certificateHolder.getSubjectPublicKeyInfo().getPublicKeyData().getBytes()));
                            // SerialNumber isi BigInteger in java and hex value in Windows/Mac/Adobe
                            System.out.println("SerialNumber: " + certificateHolder.getSerialNumber().toString(16));

                            /*FileInputStream fis = new FileInputStream("C:\\Users\\Youness\\Downloads\\sha2-ev-server-g1.crl");
                            X509CRL crl = (X509CRL) certFactory.generateCRL(fis);

                            // Create a CertPath from the certificate
                            List<X509Certificate> certList = new ArrayList<>();
                            certList.add(cert2);
                            CertPath certPath = certFactory.generateCertPath(certList);

                            // Initialize a PKIXCertPathValidatorResult using the certificate and CRL
                            PKIXParameters params = new PKIXParameters(Collections.singleton(new TrustAnchor(cert2, null)));
                            params.addCertStore(CertStore.getInstance("Collection",
                                    new CollectionCertStoreParameters(Arrays.asList(cert2, crl))));
                            params.setRevocationEnabled(true);*/

                            CertificateFactory certificateFactory2 = CertificateFactory.getInstance("X.509", new BouncyCastleProvider());
                            InputStream is = new ByteArrayInputStream(certificateHolder.getEncoded());

                            // Add Bouncy Castle as a security provider
                            Security.addProvider(new BouncyCastleProvider());
                            KeyStore keyStore = MyInstancesManager.getPKI().getKeyStore();

                            assert keyStore != null;
                            TrustAnchor ta = new TrustAnchor((X509Certificate)(keyStore.getCertificateChain("Voucher")[0]), null);


                            Set<TrustAnchor> set = Set.of(ta);
                            PKIXParameters parameters = new PKIXParameters(set);

                            //printNonCriticalExtension(cert2, "2.5.29.31");// ASCII = 0200 . ,*file:///C:/Users/Youness/Documents/crl.crl

                            try {
                                FileInputStream fis = new FileInputStream(getCRLLink(cert2));
                                X509CRL crl = (X509CRL) certFactory.generateCRL(fis);
                                System.out.println("CRL : is revoked ? "+crl.isRevoked(cert2));
                                fis.close();
                            } catch (IOException e){
                                System.out.println("probably failed to read CRL "+e.getMessage());
                            }
                            parameters.setRevocationEnabled(false);

                            ArrayList<X509Certificate> start = new ArrayList<>();
                            start.add(cert2);
                            CertificateFactory certFactory3 = CertificateFactory.getInstance("X.509");
                            CertPath certPath = certFactory3.generateCertPath(start);
                            //CertPath certPath = certificateFactory.generateCertPath(is, "PKCS7"); // Throws Certificate Exception when a cert path cannot be generated
                            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX", new BouncyCastleProvider());

                            // verifies if certificate is signed by trust anchor available in keystore.  For example jsCAexpired.cer was removed as trust anchor - all certificates signed by jsCAexpired.cer will fail the check below
                            PKIXCertPathValidatorResult validatorResult = (PKIXCertPathValidatorResult) certPathValidator.validate(certPath, parameters); // This will throw a CertPathValidatorException if validation fails
                            System.out.println("Val result:  " + validatorResult);
                            /*System.out.println("Subject was: " + cert2.getSubjectX500Principal().getName());
                            System.out.println("Issuer was:  " + cert2.getIssuerX500Principal().getName());
                            System.out.println("Trust Anchor CA Name:  " + validatorResult.getTrustAnchor().getCAName());
                            System.out.println("Trust Anchor CA:       " + validatorResult.getTrustAnchor().getCA());
                            System.out.println("Trust Anchor Issuer DN:" + validatorResult.getTrustAnchor().getTrustedCert().getIssuerDN());
                            System.out.println("Trust Anchor SubjectDN:" + validatorResult.getTrustAnchor().getTrustedCert().getSubjectDN());
                            System.out.println("Trust Cert Issuer UID:  " + validatorResult.getTrustAnchor().getTrustedCert().getIssuerUniqueID());
                            System.out.println("Trust Cert Subject UID: " + validatorResult.getTrustAnchor().getTrustedCert().getSubjectUniqueID());

                            System.out.println("Trust Cert SerialNumber: " + validatorResult.getTrustAnchor().getTrustedCert().getSerialNumber().toString(16));
                            System.out.println("Trust Cert Valid From:   " + validatorResult.getTrustAnchor().getTrustedCert().getNotBefore());
                            System.out.println("Trust Cert Valid After:  " + validatorResult.getTrustAnchor().getTrustedCert().getNotAfter());*/
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
                System.out.println();
            }
        } catch (IOException e) {
            System.err.println("Error loading PDF: " + e.getMessage());
        } finally {
            try {
                if (document != null) {
                    document.close();
                }
            } catch (IOException e) {
                System.err.println("Error closing PDF: " + e.getMessage());
            }
        }
    }
    /*public static void printNonCriticalExtension(X509Certificate cert, String oid){
        System.out.println(oid);
        byte[] extensionValue = cert.getExtensionValue(oid);
        if (extensionValue != null) {
            ASN1OctetString oct = ASN1OctetString.getInstance(extensionValue);
            System.out.println(oct);
        } else {
            System.out.println("CRL Distribution Points extension not found.");
        }
        System.out.println(" --- ");
    }*/
    private static String getCRLLink(X509Certificate cert){
        String crl=null;
        String oid="2.5.29.31";
        byte[] extensionValue = cert.getExtensionValue(oid);
        if (extensionValue != null) {
            ASN1OctetString oct = ASN1OctetString.getInstance(extensionValue);
            crl=hexToAscii(oct.toString().replace("#",""));
        }
        if(crl==null)
            return null;
        Pattern httpPattern = Pattern.compile("http(s)?://.*?\\.crl");
        Matcher httpMatcher = httpPattern.matcher(crl);
        if (httpMatcher.find()) {
            String crlUrl = httpMatcher.group();
            return crlUrl;
        }

        Pattern filePattern = Pattern.compile("file:///(.+?\\.crl)");
        Matcher fileMatcher = filePattern.matcher(crl);
        if (fileMatcher.find()) {
            String crlFilePath = fileMatcher.group(1);
            return crlFilePath;
        }
        return null;
    }
    private static String hexToAscii(String hexString) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hexString.length(); i += 2) {
            String str = hexString.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }
    public static TimeStampToken extractTimeStampToken(PDSignature signature) throws IOException, CMSException {
        byte[] content = signature.getSignedContent( new ByteArrayInputStream(signature.getContents()) );
        CMSSignedData signedData = new CMSSignedData(new CMSProcessableByteArray(content), signature.getContents());
        SignerInformation signerInfo = signedData.getSignerInfos().getSigners().iterator().next();
        AttributeTable signedAttrs = signerInfo.getSignedAttributes();
        /*if (signedAttrs == null) {
            return null;
        }*/
        Attribute timeStampAttr = signedAttrs.get(CMSAttributes.signingTime);
        System.out.println(signedAttrs.get(CMSAttributes.signingTime));
        /*if (timeStampAttr == null) {
            return null;
        }*/
        TimeStampToken timeStampToken = null;
        try {
            timeStampToken = new TimeStampToken(new CMSSignedData(timeStampAttr.getEncoded()));
        } catch (CMSException e) {
            throw new RuntimeException(e);
        } catch (TSPException e) {
            throw new RuntimeException(e);
        }
        System.out.println("AAA");
        //System.out.println(TimeStampAuthority.convertToJSON(timeStampToken));
        return timeStampToken;
    }
    /*public static boolean isValidTimeStamp(SignerInformation signerInfo) {
        AttributeTable signedAttrs = signerInfo.getSignedAttributes();
        if (signedAttrs == null) {
            return false;
        }
        Attribute timeStampAttr = signedAttrs.get(CMSAttributes.counterSignature);
        if (timeStampAttr == null) {
            return false;
        }
        TimeStampToken timeStampToken = null;
        try {
            timeStampToken = TimeStampToken.getInstance(timeStampAttr.getAttrValues().getObjectAt(0));
        } catch (IOException e) {
            return false;
        }
        // Validate the time stamp token's signature using the signer's certificate
        SignerInformationVerifier verifier = null;
        try {
            verifier = new JcaSimpleSignerInfoVerifierBuilder().build(signerInfo.getDigestAlgOID(), signerInfo.ge);
        } catch (OperatorCreationException e) {
            return false;
        }
        if (!timeStampToken.isSignatureValid(verifier)) {
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
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException | CertStoreException e) {
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
        CertPathBuilder builder = null;
        try {
            builder = CertPathBuilder.getInstance("PKIX", "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            return false;
        }
        try {
            builder.build(new X509CertSelector(), CertPathBuilderValidator.getCertPathParameters(certs));
        } catch (CertPathBuilderException e) {
            return false;
        }
        return true;
    }*/
}
