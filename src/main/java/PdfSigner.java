import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Collections;

public class PdfSigner {
    public static void main(String[] args) {
        String alias = "AlphaTester", password="password123", path="C:\\Users\\Youness\\Downloads\\MyPdfTest.pdf";
        try {
            if(!RootCertHandler.getKeyStore().containsAlias(alias))
                ChildCertsHandler.generateCert(RootCertHandler.rootAlias, RootCertHandler.rootPasswordRaw, "cn=Youness", 24*365, alias, password);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        try{
            KeyStore ks = RootCertHandler.getKeyStore();

            Certificate[] certChain = ks.getCertificateChain(alias);
            X509Certificate certificate = (X509Certificate) certChain[0];

            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());

            signDoc(path, certificate, privateKey);

        } catch (UnrecoverableKeyException e) {
            throw new RuntimeException(e);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public static void signDoc(String path, X509Certificate certificate, PrivateKey privateKey){
        PDDocument document=null;
        //FileInputStream fis;
        File signedFile= new File(path);
        //fis = new FileInputStream(f);
        try {
            document = PDDocument.load(signedFile);

            PDSignature signature = new PDSignature();
            signature.setType(COSName.DOC_TIME_STAMP);
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setSignDate(Calendar.getInstance());


            SignatureInterface signatureInterface = new SignatureInterface() {
                @Override
                public byte[] sign(InputStream content) throws IOException {
                    try {
                        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(privateKey);
                        generator.addSignerInfoGenerator(
                                new JcaSignerInfoGeneratorBuilder(
                                        new JcaDigestCalculatorProviderBuilder().build())
                                        .build(signer, certificate));
                        generator.addCertificates(new JcaCertStore(Collections.singleton(certificate)));
                        CMSProcessableByteArray inputStream = new CMSProcessableByteArray(content.readAllBytes());
                        CMSSignedData signedData = generator.generate(inputStream, false);
                        return signedData.getEncoded();
                    } catch (OperatorCreationException | CMSException |
                             CertificateException e) {
                        throw new RuntimeException(e);
                    }
                }
            };

            document.addSignature(signature, signatureInterface);

            String newPath = signedFile.getParent() + "/" +
                    signedFile.getName().replace(".", "2.");

            document.saveIncremental(new FileOutputStream(new File(newPath)));


        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
