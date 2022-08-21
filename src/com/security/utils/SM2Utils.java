package com.security.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Enumeration;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.math.ec.ECPoint;

import com.security.SM2Cipher;
import com.security.SM2Result;
import com.security.SM3Digest;
import com.security.math.SM2;

/**
 * @author ren365880
 */
public class SM2Utils {
	public static byte[] encrypt(byte[] publicKey, byte[] data) throws IOException {
		if (publicKey == null || publicKey.length == 0) {
			return null;
		}

		if (data == null || data.length == 0) {
			return null;
		}

		byte[] source = new byte[data.length];
		System.arraycopy(data, 0, source, 0, data.length);

		SM2Cipher cipher = new SM2Cipher();
		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

		ECPoint c1 = cipher.init_enc(sm2, userKey);
		cipher.update_encrypt(source);
		byte[] c3 = new byte[32];
		cipher.doFinal(c3);

		DERInteger x = new DERInteger(c1.getX().toBigInteger());
		DERInteger y = new DERInteger(c1.getY().toBigInteger());
		DEROctetString derDig = new DEROctetString(c3);
		DEROctetString derEnc = new DEROctetString(source);
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(x);
		v.add(y);
		v.add(derDig);
		v.add(derEnc);
		DERSequence seq = new DERSequence(v);
		ByteArrayOutputStream bos = new ByteArrayOutputStream();
		DEROutputStream dos = new DEROutputStream(bos);
		dos.writeObject(seq);
		return bos.toByteArray();
	}

	public static byte[] decrypt(byte[] privateKey, byte[] encryptedData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (encryptedData == null || encryptedData.length == 0) {
			return null;
		}

		byte[] enc = new byte[encryptedData.length];
		System.arraycopy(encryptedData, 0, enc, 0, encryptedData.length);

		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(1, privateKey);

		ByteArrayInputStream bis = new ByteArrayInputStream(enc);
		ASN1InputStream dis = new ASN1InputStream(bis);
		DERObject derObj = dis.readObject();
		ASN1Sequence asn1 = (ASN1Sequence) derObj;
		DERInteger x = (DERInteger) asn1.getObjectAt(0);
		DERInteger y = (DERInteger) asn1.getObjectAt(1);
		ECPoint c1 = sm2.ecc_curve.createPoint(x.getValue(), y.getValue(), true);

		SM2Cipher cipher = new SM2Cipher();
		cipher.init_dec(userD, c1);
		DEROctetString data = (DEROctetString) asn1.getObjectAt(3);
		enc = data.getOctets();
		cipher.update_decrypt(enc);
		byte[] c3 = new byte[32];
		cipher.doFinal(c3);
		return enc;
	}

	public static byte[] sign(byte[] userId, byte[] privateKey, byte[] sourceData) throws IOException {
		if (privateKey == null || privateKey.length == 0) {
			return null;
		}

		if (sourceData == null || sourceData.length == 0) {
			return null;
		}

		SM2 sm2 = SM2.Instance();
		BigInteger userD = new BigInteger(privateKey);

		ECPoint userKey = sm2.ecc_point_g.multiply(userD);

		SM3Digest sm3 = new SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);

		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
		byte[] md = new byte[32];
		sm3.doFinal(md, 0);

		SM2Result sm2Result = new SM2Result();
		sm2.sm2Sign(md, userD, userKey, sm2Result);

		DERInteger d_r = new DERInteger(sm2Result.r);
		DERInteger d_s = new DERInteger(sm2Result.s);
		ASN1EncodableVector v2 = new ASN1EncodableVector();
		v2.add(d_r);
		v2.add(d_s);
		DERObject sign = new DERSequence(v2);
		byte[] signdata = sign.getDEREncoded();
		return signdata;
	}

	@SuppressWarnings("unchecked")
	public static boolean verifySign(byte[] userId, byte[] publicKey, byte[] sourceData, byte[] signData)
			throws IOException {
		if (publicKey == null || publicKey.length == 0) {
			return false;
		}

		if (sourceData == null || sourceData.length == 0) {
			return false;
		}

		SM2 sm2 = SM2.Instance();
		ECPoint userKey = sm2.ecc_curve.decodePoint(publicKey);

		SM3Digest sm3 = new SM3Digest();
		byte[] z = sm2.sm2GetZ(userId, userKey);
		sm3.update(z, 0, z.length);
		sm3.update(sourceData, 0, sourceData.length);
		byte[] md = new byte[32];
		sm3.doFinal(md, 0);

		ByteArrayInputStream bis = new ByteArrayInputStream(signData);
		ASN1InputStream dis = new ASN1InputStream(bis);
		DERObject derObj = dis.readObject();
		Enumeration<DERInteger> e = ((ASN1Sequence) derObj).getObjects();
		BigInteger r = ((DERInteger) e.nextElement()).getValue();
		BigInteger s = ((DERInteger) e.nextElement()).getValue();
		SM2Result sm2Result = new SM2Result();
		sm2Result.r = r;
		sm2Result.s = s;

		sm2.sm2Verify(md, userKey, sm2Result.r, sm2Result.s, sm2Result);
		return sm2Result.r.equals(sm2Result.R);
	}

}
