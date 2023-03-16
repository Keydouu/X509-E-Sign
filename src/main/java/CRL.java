import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.*;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Locale;

public class CRL {
    protected final static String crlPath="C:\\Users\\Youness\\Documents\\crl.crl";
    protected final static String crlURI="file:///C:/Users/Youness/Documents/crl.crl";
    protected static void generateCRL(PrivateKey pk) throws OperatorCreationException, CRLException, IOException {
        X509v2CRLBuilder crlB= new X509v2CRLBuilder(new X500Name("cn=EAI Root CA\no=EURAFRIC INFORMATION\nc=MA"), new Date(System.currentTimeMillis()), new Locale("fr","MA"));
        X509CRLHolder crlH = crlB.build(new JcaContentSignerBuilder("SHA256withRSA").build(pk));
        X509CRL crl = new JcaX509CRLConverter().getCRL(crlH);
        File crlFile = new File(crlPath);
        if (!crlFile.getParentFile().exists()) {
            crlFile.getParentFile().mkdirs();
        }
        FileOutputStream fos = new FileOutputStream(crlFile);
        byte[] crlBytes = crl.getEncoded();
        fos.write(crlBytes);
        fos.close();
    }

    protected static void addToCRL(BigInteger serialNumber, Date revocationDate, int reason){
        try {
            FileInputStream fis = new FileInputStream(crlPath);
            X509CRLHolder crl = new X509CRLHolder(fis);
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(crl);
            crlBuilder.addCRLEntry(serialNumber, revocationDate, reason);
            X509CRLHolder crlH = crlBuilder.build(new JcaContentSignerBuilder("SHA256withRSA").build((PrivateKey) RootInitializer.getRootCertKey()));
            X509CRL x509crl = new JcaX509CRLConverter().getCRL(crlH);
            fis.close();
            FileOutputStream fos = new FileOutputStream("crlPath");
            byte[] crlBytes = x509crl.getEncoded();
            fos.write(crlBytes);
            fos.close();
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (CRLException e) {
            throw new RuntimeException(e);
        } catch (OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }
    protected static X509CRLHolder getCRLHolder(){
        FileInputStream fis = null;
        X509CRLHolder crl = null;
        try {
            fis = new FileInputStream(crlPath);
            crl = new X509CRLHolder(fis);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        return crl;
    }
}
