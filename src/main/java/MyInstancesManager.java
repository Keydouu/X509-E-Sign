import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jetbrains.annotations.NotNull;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

public class MyInstancesManager {
    private final static String timeStampAlias="Kronos2";
    private final static char[] timeStampPassword="TimeManagement2".toCharArray();
    private final static char[] keystorePassword="password_16556)('.-((-".toCharArray() ;
    private final static String keystoreFilePath = "C:\\Users\\Youness\\Documents\\kys.p12";
    private final static String rootAlias="Genesis";
    private final static char[] rootPasswordRaw="root00Passwo0ordR4awYC99_1656)('.-((-".toCharArray();
    private final static String certSignerAlias="Voucher";
    private final static char[] certSignerPassword="ISwearThisIsValid".toCharArray();
    private final static String crlPath="C:\\Users\\Youness\\Documents\\crl.crl";
    private final static String crlURI="file:///C:/Users/Youness/Documents/crl.crl";



    private final static String cryptAlg="RSA";
    private final static String hashAndCryptAlg="SHA256WithRSA";
    private final static ASN1ObjectIdentifier algOID = new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1");
    private final static String policyOid = "1.2.840.113549.1.9.16.1.4";//"1.2"; //



    private static PublicKeyInfrastructure publicKeyInfrastructure;
    private static TimeStampAuthority timeStampAuthority;
    private static CertificateChainAndPrivateKey signingCert;
    private static X509CertificatesGenerator certGen;

    public static void initialiseALl(){
        if(!(new File(keystoreFilePath)).exists())
            generateCAcerts();
        else
            publicKeyInfrastructure = new PublicKeyInfrastructure(rootAlias, rootPasswordRaw, keystorePassword, keystoreFilePath, new CertificatesRevocationsList(crlPath, crlURI), rootTrustAnchorName);

        try {
            timeStampAuthority=new TimeStampAuthority(
                    new CertificateChainAndPrivateKey(CertificateChainAndPrivateKey.toX509Chain(publicKeyInfrastructure.getKeyStore().getCertificateChain(timeStampAlias)),
                            (PrivateKey) publicKeyInfrastructure.getKeyStore().getKey(timeStampAlias, timeStampPassword)),
                    hashAndCryptAlg, algOID, policyOid);

            signingCert=new CertificateChainAndPrivateKey(CertificateChainAndPrivateKey.toX509Chain(publicKeyInfrastructure.getKeyStore().getCertificateChain(certSignerAlias)),
                    (PrivateKey) publicKeyInfrastructure.getKeyStore().getKey(certSignerAlias, certSignerPassword));
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
        certGen=new X509CertificatesGenerator(publicKeyInfrastructure, signingCert);



        /*certGen.generateCert(
                "cn=AC Global Time Stamp,o=EURAFRIC INFORMATION,c=MA", 5*24*365,
                timeStampAlias, timeStampPassword, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));*/
    }
    protected static TimeStampAuthority getTSA(){return timeStampAuthority;}
    protected static PublicKeyInfrastructure getPKI(){return publicKeyInfrastructure;}
    protected static X509CertificatesGenerator getCertGen(){return certGen;}
    protected static CertificateChainAndPrivateKey getSigningCert(){return signingCert;}




    /*
    *
    * This part is about generating Keystore file, CRL file, root certificate,
    * the middle certificate that sign clients certificates
    * and time stamp authority certificate
    *
    * it is executed if the keystore file does not exist
    *
    * */

    private final static String rootTrustAnchorName = "cn=Keydou's Root CA,o=DATA,c=MA";
    private final static String signerAName = "cn=Keydou's e stamp,o=DATA,c=MA";
    private final static String timeStampAuthorityName = "cn=Keydou's TSA,o=DATA,c=MA";

    private static void generateCAcerts(){
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, keystorePassword);


            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(cryptAlg);
            keyPairGenerator.initialize(2048, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            //myPrivateKey = keyPair.getPrivate();
            new CertificatesRevocationsList(crlPath, crlURI).generateCRL(keyPair.getPrivate(), new X500Name(rootTrustAnchorName));

            X509Certificate rootCertificate = generateRootCert(crlURI, new X500Principal(rootTrustAnchorName),
                    keyPair, hashAndCryptAlg);
            keyStore.setKeyEntry(rootAlias, keyPair.getPrivate(), rootPasswordRaw, new Certificate[]{rootCertificate});


            FileOutputStream fos = new FileOutputStream(keystoreFilePath);
            keyStore.store(fos, keystorePassword);
            fos.close();

            publicKeyInfrastructure = new PublicKeyInfrastructure(rootAlias, rootPasswordRaw, keystorePassword, keystoreFilePath, new CertificatesRevocationsList(crlPath, crlURI), rootTrustAnchorName);
            certGen=new X509CertificatesGenerator(publicKeyInfrastructure);
            certGen.generateCert(signerAName, 5*24*365, certSignerAlias, certSignerPassword,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyCertSign | KeyUsage.nonRepudiation));

            certGen.generateCert(timeStampAuthorityName, 5*24*365, timeStampAlias, timeStampPassword,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation), true);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    private static X509Certificate generateRootCert(String crlURI, X500Principal x500principal, KeyPair rootKeyPair,
                                                    String hashAndCryptAlg){
        try {
            BigInteger rootSerialNumber = generateTheShittySerialNumber();
            //System.out.println(rootSerialNumber);
            long now = System.currentTimeMillis();
            Date rootStartDate = new Date(now); //yesterday
            Date rootEndDate = new Date(now + 5L * 365 * 24 * 60 * 60 * 5000); // 10 years after today
            X509v3CertificateBuilder rootCertBuilder = new JcaX509v3CertificateBuilder(
                    x500principal, rootSerialNumber, rootStartDate, rootEndDate, x500principal, rootKeyPair.getPublic());//no java.util.Locale localDate
            rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));//isCA = true
            rootCertBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

            //rootCertBuilder.addExtension(Extension.subjectAlternativeName, false, new GeneralName(GeneralName.dNSName, "localhost")); ???
            ASN1ObjectIdentifier cRLDistributionPoints = new ASN1ObjectIdentifier("2.5.29.31");
            DistributionPoint[] points = new DistributionPoint[1];
            points[0] = new DistributionPoint(new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlURI))),null, null);
            rootCertBuilder.addExtension(cRLDistributionPoints, true, new CRLDistPoint(points));


            // Create the Authority Key Identifier extension
            SubjectPublicKeyInfo caPublicKeyInfo = SubjectPublicKeyInfo.getInstance(rootKeyPair.getPublic().getEncoded());
            AuthorityKeyIdentifier authorityKeyIdentifier = new AuthorityKeyIdentifier(caPublicKeyInfo);

            // Add the extension to the certificate builder
            rootCertBuilder.addExtension(
                    org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier,
                    false,
                    authorityKeyIdentifier
            );

            ContentSigner rootCertSigner = new JcaContentSignerBuilder(hashAndCryptAlg).build(rootKeyPair.getPrivate());
            X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertSigner);
            X509Certificate rootCert = new JcaX509CertificateConverter().getCertificate(rootCertHolder);
            return rootCert;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }  catch (CertificateEncodingException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (CertIOException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    @NotNull
    protected static BigInteger secretKeyToSerialNumber(@NotNull String secretKey){
        byte[] decoded = Base64.getDecoder().decode(secretKey);
        return new BigInteger(1, decoded);
    }
    private static BigInteger generateTheShittySerialNumber() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256); // for example
        SecretKey secretKey = keyGen.generateKey();
        //String secretKey = "UmLMeGR1sWeuxknWbMyFJQ==";
        return MyInstancesManager.secretKeyToSerialNumber(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
    }
}
