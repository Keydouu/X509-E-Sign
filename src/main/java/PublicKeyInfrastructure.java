
import java.io.*;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;

public class PublicKeyInfrastructure {
    private KeyStore keyStore;
    private char[] keystorePassword;
    protected String keystoreFilePath;
    protected String rootAlias;
    private char[] rootPassword;
    private CertificatesRevocationsList myCRL;
    private String name;
    private CertificateChainAndPrivateKey myCert;
    public PublicKeyInfrastructure(String rootAlias, char[] rootPassword, char[] keystorePassword, String keystoreFilePath,
                                   CertificatesRevocationsList crl, String name){
        this.rootAlias=rootAlias;
        this.rootPassword=rootPassword;
        this.keystoreFilePath=keystoreFilePath;
        this.keystorePassword=keystorePassword;
        this.myCRL=crl;
        this.name=name;

        File keystoreFile = new File(keystoreFilePath);

        try {
            this.keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new FileInputStream(keystoreFile), keystorePassword);
            this.myCert=new CertificateChainAndPrivateKey(new X509Certificate[]{(X509Certificate)this.keyStore.getCertificateChain(this.rootAlias)[0]}
                    , (PrivateKey) this.keyStore.getKey(this.rootAlias, this.rootPassword));
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        }
    }
    protected KeyStore getKeyStore(){return this.keyStore;}
    protected CertificateChainAndPrivateKey getCert(){return this.myCert;}
    protected CertificatesRevocationsList getCRL(){return this.myCRL;}


    protected void insertIntoKeyStore(String alias, PrivateKey privateKey, Certificate[] chain, char[] password){
        try {
            this.keyStore.setKeyEntry(alias, privateKey, password, chain);
            FileOutputStream fos = new FileOutputStream(this.keystoreFilePath);
            this.keyStore.store(fos, this.keystorePassword);
            fos.close();
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    /*@NotNull
    protected static String serialNumberToSecretKey(@NotNull BigInteger serialNumber){
        byte[] bytes = serialNumber.toByteArray();
        return Base64.getEncoder().encodeToString(bytes);
    }
    protected static SecretKey getSecretKey(String alias) throws KeyStoreException {
        X509Certificate cert = (X509Certificate)RootCertHandler.getKeyStore().getCertificateChain(alias)[0];
        byte[] decodedKey = serialNumberToSecretKey(cert.getSerialNumber()).getBytes();
        SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        return secretKey;
    }*/
}
