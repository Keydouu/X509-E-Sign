import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPException;

import java.io.*;
import java.security.cert.Certificate;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Calendar;

public class PdfSigner {
    public static void main(String[] args) {
        MyInstancesManager.initialiseALl();

        String alias = "AlphaTester", password="password123", path="C:\\Users\\Youness\\Downloads\\MyPdfTest.pdf";
        try {
            if(!MyInstancesManager.getPKI().getKeyStore().containsAlias(alias))
                MyInstancesManager.getCertGen().generateCert("cn=Youness,c=MA", 24*365, alias,
                        password.toCharArray(), new KeyUsage(KeyUsage.nonRepudiation));
            //keyEncipherment
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        try{
            KeyStore ks = MyInstancesManager.getPKI().getKeyStore();

            Certificate[] certChain = ks.getCertificateChain(alias);
            X509Certificate c1 = (X509Certificate) certChain[0];
            X509Certificate c2 = (X509Certificate) certChain[1];
            X509Certificate c3 = (X509Certificate) certChain[2];


            PrivateKey privateKey = (PrivateKey) ks.getKey(alias, password.toCharArray());

            signDoc(path, certChain, privateKey);

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

    public static void signDoc(String path, Certificate[] certChain, PrivateKey privateKey){
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
                                        .build(signer, (X509Certificate) certChain[0]));
                        generator.addCertificates(new JcaCertStore(Arrays.asList(certChain)));
                        byte[] doc=content.readAllBytes();
                        //generator.addCRL(RootInitializer.getCRLHolder());


                        CMSProcessableByteArray inputStream = new CMSProcessableByteArray(doc);
                        CMSSignedData signedData = generator.generate(inputStream, false);

                        signedData = MyInstancesManager.getTSA().signTimeStamps(signedData);
                        //Attribute tokenAttr = TimeStampAuthority.createTSTokenAttribute(signedData.getEncoded());

                        return signedData.getEncoded();
                    } catch (OperatorCreationException | CMSException | CertificateException e) {
                        throw new RuntimeException(e);
                    } catch (TSPException e) {
                        throw new RuntimeException(e);
                    }
                }
            };

            document.addSignature(signature, signatureInterface);

            String newPath = signedFile.getParent() + "/" +
                    signedFile.getName().replace(".", " Signed2.");

            document.saveIncremental(new FileOutputStream(new File(newPath)));


        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

}
