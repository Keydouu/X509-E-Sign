import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

public class CertificateChainAndPrivateKey {
    private X509Certificate myCert;
    private X509Certificate[] myCertChain;
    private PrivateKey pk;

    public CertificateChainAndPrivateKey(X509Certificate[] myCertChain) {
        this.myCertChain = myCertChain;
        this.myCert = myCertChain[0];
    }

    public CertificateChainAndPrivateKey(X509Certificate[] myCertChain, PrivateKey pk) {
        this.myCertChain = myCertChain;
        this.myCert = myCertChain[0];
        this.pk = pk;
    }

    public PrivateKey getPk() {
        return pk;
    }

    public X509Certificate getMyCert() {
        return myCert;
    }

    public X509Certificate[] getMyCertChain() {
        return myCertChain;
    }
    public static X509Certificate[] toX509Chain(Certificate[] chain){
        X509Certificate[] newChain = new X509Certificate[chain.length];
        for (int i = 0; i < newChain.length; i++) {
            newChain[i] = (X509Certificate) chain[i];
        }
        return newChain;
    }
}
