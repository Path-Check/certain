package de.tsenger.certain.asn1.eac;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.DERSequence;

public class DiscretionaryDataTemplate extends ASN1Object {

	private ASN1ObjectIdentifier oid;
	private byte[] discretionaryData;

	public DiscretionaryDataTemplate(ASN1ObjectIdentifier oid, byte[] data) {
		this.oid = oid;
		this.discretionaryData = data;

	}

	private DiscretionaryDataTemplate(DERApplicationSpecific appSpe) throws IOException {
		setDiscretionaryData(appSpe);
	}

	private void setDiscretionaryData(DERApplicationSpecific appSpe) throws IOException {
		if (appSpe.getApplicationTag() == EACTags.DISCRETIONARY_DATA_TEMPLATE) {

			ASN1InputStream content = new ASN1InputStream(appSpe.getContents());
			ASN1Primitive tmpObj;

			while ((tmpObj = content.readObject()) != null) {

				if (tmpObj instanceof ASN1ObjectIdentifier)
					oid = ASN1ObjectIdentifier.getInstance(tmpObj);

				if (tmpObj instanceof DERApplicationSpecific) {
					DERApplicationSpecific aSpe = (DERApplicationSpecific) tmpObj;
					if (aSpe.getApplicationTag() == EACTags.DISCRETIONARY_DATA) {
						discretionaryData = aSpe.getContents();
					} else {
						content.close();
						throw new IOException("Invalid Object, no discretionaray data");
					}
				}
			}
			content.close();
		} else
			throw new IOException("not a DISCRETIONARY DATA TEMPLATE :" + appSpe.getApplicationTag());
	}

	public byte[] getDiscretionaryData() {
		return discretionaryData;
	}

	public static DiscretionaryDataTemplate getInstance(Object obj) throws IOException {
		if (obj instanceof DiscretionaryDataTemplate) {
			return (DiscretionaryDataTemplate) obj;
		} else if (obj != null) {
			return new DiscretionaryDataTemplate(DERApplicationSpecific.getInstance(obj));
		}

		return null;
	}

	@Override
	public ASN1Primitive toASN1Primitive() {
		ASN1EncodableVector v = new ASN1EncodableVector();
		v.add(oid);
		v.add(new DERApplicationSpecific(EACTags.DISCRETIONARY_DATA, discretionaryData));
		try {
			return new DERApplicationSpecific(false, EACTags.DISCRETIONARY_DATA_TEMPLATE, new DERSequence(v));
		} catch (IOException e) {
			throw new IllegalStateException("unable to convert Discretionary Data Template");
		}
	}

}
