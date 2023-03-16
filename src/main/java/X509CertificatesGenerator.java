import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.*;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class X509CertificatesGenerator {
    public static boolean generateClientCert( String subjectName, long hoursOfValidity, String alias, char[] password) throws KeyStoreException {
        if(RootInitializer.getKeyStore().containsAlias(alias))
            return false;
        generateCert(RootInitializer.certSignerAlias, RootInitializer.certSignerPassword, subjectName, hoursOfValidity,
                alias, password, new KeyUsage(KeyUsage.nonRepudiation | KeyUsage.digitalSignature));
        return true;
    }
    protected static void generateCert(String signerAlias, char[] signerPassword, String subjectName, long hoursOfValidity, String subjectAlias, char[] password, KeyUsage keyUsage){
        try {
            Certificate[] chain = RootInitializer.getKeyStore().getCertificateChain(signerAlias);
            X509Certificate rootCertificate = (X509Certificate) chain[0];

            // Generate CSR
            KeyPairGenerator keyPairGenerator = null;
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            KeyPair entityKeyPair = keyPairGenerator.generateKeyPair();

            //PKCS10CertificationRequest csr = generateCSR(entityKeyPair, entitySubjectDN);
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256); // for example
            SecretKey secretKey = keyGen.generateKey();
            //String secretKey = "UmLMeGR1sWeuxknWbMyFJQ==";
            BigInteger rootSerialNumber = RootInitializer.secretKeyToSerialNumber(Base64.getEncoder().encodeToString(secretKey.getEncoded()));

            // Generate new certificate using the root key pair
            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    rootCertificate.getSubjectX500Principal(), rootSerialNumber, new Date(System.currentTimeMillis()),
                    new Date(System.currentTimeMillis() + hoursOfValidity * 60L * 60 * 1000), new X500Principal(subjectName),
                    entityKeyPair.getPublic());
            if(keyUsage.hasUsages(KeyUsage.keyCertSign))
                certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            else
                certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));//isCA = true
            certBuilder.addExtension(Extension.keyUsage, true, keyUsage);

            if(subjectAlias.equals(TimeStampAuthority.timeStampAlias))
                certBuilder.addExtension(Extension.extendedKeyUsage, true, new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));


            ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");
            DistributionPoint[] points = new DistributionPoint[1];
            points[0] = new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, CRL.crlURI))),null, null);
            certBuilder.addExtension(cRLDistributionPoints, true, new CRLDistPoint(points));


            // Create the Authority Key Identifier extension
            SubjectPublicKeyInfo caPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rootCertificate.getPublicKey().getEncoded());
            AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier(caPublicKeyInfo);

            // Add the extension to the certificate builder
            certBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                    false,
                    authorityKeyIdentifier
            );

            JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder("SHA256withRSA");

            //ERROR ERROR ERROR ERROR
            ContentSigner certSigner = certSignerBuilder.build((PrivateKey) RootInitializer.getKeyStore().getKey(signerAlias,
                    signerPassword));
            X509CertificateHolder certHolder= certBuilder.build(certSigner);

            X509Certificate entityCertificate =  new JcaX509CertificateConverter().getCertificate(certHolder);

            //saving in keystore
            Certificate[] newChain = new X509Certificate[chain.length+1];
            newChain[0]=entityCertificate;
            for (int i = 1; i < newChain.length; i++) {
                newChain[i] = chain[i-1];
            }
            RootInitializer.insertIntoKeyStore(subjectAlias, entityKeyPair.getPrivate(), newChain, password);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
