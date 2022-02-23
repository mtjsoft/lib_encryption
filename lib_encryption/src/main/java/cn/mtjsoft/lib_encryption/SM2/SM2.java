package cn.mtjsoft.lib_encryption.SM2;

import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.FixedPointCombMultiplier;
import org.bouncycastle.math.ec.WNafUtil;
import org.bouncycastle.pqc.math.linearalgebra.ByteUtils;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * @author mtj
 * @date 2021/8/12
 * @desc
 * @email mtjsoft3@gmail.com
 */
class SM2 {
    private final ECCurve mCurve;

    private final ECDomainParameters mDomainParams;

    private final ECKeyPairGenerator mKeyPairGenerator;

    private final ECPoint mECPoint_G;

    private SM2() {
        X9ECParameters x9 = ECNamedCurveTable.getByName("sm2p256v1");
        this.mCurve = x9.getCurve();
        this.mECPoint_G = x9.getG();
        this.mDomainParams = new ECDomainParameters(x9.getCurve(), x9.getG(), x9.getN(), x9.getH(), x9.getSeed());
        ECKeyGenerationParameters ecc_ecgenparam = new ECKeyGenerationParameters(this.mDomainParams, new SecureRandom());
        this.mKeyPairGenerator = new ECKeyPairGenerator();
        this.mKeyPairGenerator.init(ecc_ecgenparam);
    }

    static SM2 Instance() {
        return Holder.INSTANCE;
    }

    ECPublicKeyParameters getPublicKeyParameters(byte[] publicKey) {
        if (publicKey.length == 64) {
            publicKey = ByteUtils.concatenate(new byte[] { SM2Util.MODE_NO_COMPRESS }, publicKey);
        }

        ECPoint q = this.mCurve.decodePoint(publicKey);
        return new ECPublicKeyParameters(q, this.mDomainParams);
    }

    ECPrivateKeyParameters getPrivateKeyParameters(byte[] privateKey) {
        BigInteger d = new BigInteger(1, privateKey);
        return new ECPrivateKeyParameters(d, this.mDomainParams);
    }

    AsymmetricCipherKeyPair generateKeyPair() {
        return this.mKeyPairGenerator.generateKeyPair();
    }

    byte[] getPublicKeyFromPrivateKey(byte[] privateKey) {
        BigInteger d = new BigInteger(1, privateKey);
        ECPoint Q = (new FixedPointCombMultiplier()).multiply(this.mECPoint_G, d);
        byte[] publicKeyEncoded = Q.getEncoded(false);
        if (publicKeyEncoded.length == 65) {
            publicKeyEncoded = ByteUtils.subArray(publicKeyEncoded, 1, publicKeyEncoded.length);
        }

        return publicKeyEncoded;
    }

    boolean isValidPrivateKey(byte[] privateKey) {
        BigInteger d = new BigInteger(1, privateKey);
        BigInteger n = this.mDomainParams.getN();
        return d.compareTo(BigInteger.ONE) >= 0 && d.compareTo(n) < 0;
    }

    private static final class Holder {
        private static final SM2 INSTANCE = new SM2();

        private Holder() {
        }
    }
}
