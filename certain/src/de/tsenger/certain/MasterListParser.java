package de.tsenger.certain;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertSelector;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import de.tsenger.tools.HexString;

public class MasterListParser {
	

	
	private List<Certificate> masterListSignerCertificates;
	private List<Certificate> cscaCerts;
	private CMSSignedData cmsSignedData;
	private SignerInformation signerInfo;

	/** Use this to get all certificates, including link certificates. */
	private static final CertSelector IDENTITY_SELECTOR = new X509CertSelector() {
		@Override
		public boolean match(Certificate cert) {
			if (!(cert instanceof X509Certificate)) { return false; }
			return true;
		}

		@Override
		public Object clone() { return this; }	
	};

	/** Use this to get self-signed certificates only. (Excludes link certificates.) */
	private static final CertSelector SELF_SIGNED_SELECTOR = new X509CertSelector() {
		@Override
		public boolean match(Certificate cert) {
			if (!(cert instanceof X509Certificate)) { return false; }
			X509Certificate x509Cert = (X509Certificate)cert;
			X500Principal issuer = x509Cert.getIssuerX500Principal();
			X500Principal subject = x509Cert.getSubjectX500Principal();
			return (issuer == null && subject == null) || subject.equals(issuer);
		}

		@Override
		public Object clone() { return this; }
	};

	/** Private constructor, only used locally. */
	private MasterListParser() {
		cscaCerts = new ArrayList<Certificate>(256);
		masterListSignerCertificates  = new ArrayList<Certificate>(4);
	}
	
	public MasterListParser(byte[] binary, CertSelector selector) {
		this();
		
		this.cmsSignedData = buildCMSSignedDataFromBinary(binary);		
		this.signerInfo = parseSignerInfo();
		this.cscaCerts = parseMasterList();
		this.masterListSignerCertificates = parseMasterListSignerCertificates();		

	}
	
	public MasterListParser(byte[] binary) {
		this(binary, IDENTITY_SELECTOR);
	}
	
	
	public List<Certificate> getMasterListSignerCertificates() {
		return masterListSignerCertificates;
	}
	
	public List<Certificate> getCSCACertificates() {
		return cscaCerts;
	}

	protected static String toPEM(String type, byte[] data) throws IOException {
		final PemObject pemObject = new PemObject(type, data);
		final StringWriter sw = new StringWriter();
		try (final PemWriter pw = new PemWriter(sw)) {
			pw.writeObject(pemObject);
		}
		return sw.toString();
	}

	private String getCountryName(X509Certificate x509Cert) {
		Map<String, String> oidMap = new HashMap<String, String>();
		oidMap.put("2.5.4.6", "MY_INDISTINGUISHABLE_ID");
		String name = x509Cert.getIssuerX500Principal().getName("RFC1779", oidMap);

		int start = name.indexOf("MY_INDISTINGUISHABLE_ID");
		int end = name.indexOf(",", start);
		if (end == -1) {
				end = name.length();
		}
		return name.substring(start + "MY_INDISTINGUISHABLE_ID".length()+1, end);
	}

	private void printTrustEntry(StringWriter sw, X509Certificate x509Cert, Set<String> pkiInserted) {
		try {
			DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
			SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());

			String b64SKI = Base64.getEncoder().encodeToString(skid.getKeyIdentifier());

			DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

			String countryCode = getCountryName(x509Cert);
			String countryName = new Locale("en", countryCode).getDisplayCountry();
			String id = countryCode + "#" + b64SKI;

			/**
			 * "AUS#NhfB5/VnlXEuN3VwjlWDMYbpOA4=": {
					"displayName": {
						"en": "Gov of Australia"
					},
					"entityType": "issuer",
					"status": "current",
					"validFromDT": "2021-08-31T14:00:00.000Z",
					"validUntilDT": "2031-09-30T13:59:59.000Z",
					"didDocument": "-----BEGIN CERTIFICATE-----\n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\n-----END CERTIFICATE-----",
					"credentialType": [
						"icao.vacc",
						"icao.test"
					]
				}
			 */

			if (pkiInserted.contains(id)) return;

			pkiInserted.add(id);

			
			sw.write("    \"" +id+ "\": { \n");
			sw.write("      \"displayName\": {\n");
			sw.write("        \"en\": \"Gov of "+countryName+"\"\n");
			sw.write("      },\n");
			sw.write("      \"entityType\": \"issuer\",\n");
			sw.write("      \"status\": \"current\",\n");
			sw.write("      \"validFromDT\": \""+ formatter.format(x509Cert.getNotBefore()) +"\",\n");
			sw.write("      \"validUntilDT\": \""+ formatter.format(x509Cert.getNotAfter()) +"\",\n");
			sw.write("      \"didDocument\": \"" + toPEM("CERTIFICATE", x509Cert.getEncoded()).replaceAll("\n", "\\\\n") + "\",\n");
			sw.write("      \"credentialType\": [\n");
			sw.write("      	\"icao.vacc\",\n");
			sw.write("      	\"icao.test\"\n");
			sw.write("      ]\n");
			sw.write("    },\n");
			
			//swTrust

		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
	}
	
	public String getMasterListInfoString(boolean showDetails, String filterBySubject) {
			
		StringWriter sw = new StringWriter();

		StringWriter swTrust = new StringWriter();
		
		int i=0;
		
		
		sw.append("\nThis Master List contains "+cscaCerts.size()+" CSCA certificates. \nand "+masterListSignerCertificates.size()+" Master List Signer Certificates.\n\n");
		
		for (Certificate mlSigner : masterListSignerCertificates) {
			X509Certificate x509Cert = (X509Certificate) mlSigner;
			String subjectDN = x509Cert.getSubjectDN().toString();
			String issuerDN = x509Cert.getIssuerDN().toString();
			DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
			SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());

			String b64SKI = Base64.getEncoder().encodeToString(skid.getKeyIdentifier());
			String hexSKI = HexString.bufferToHex(skid.getKeyIdentifier());

			if (filterBySubject == null || b64SKI.equals(filterBySubject) || hexSKI.equals(filterBySubject)) {
				sw.append("+++++++++++++ Masterlist Signer Cert no. "+(++i)+" ++++++++++++++\n");
				sw.write("Subject DN: "+subjectDN+"\n");
				sw.write("Issuer  DN:  "+issuerDN+"\n");
			
				sw.write("X509 SubjectKeyIdentifier B64: "+ b64SKI + "\n");
				sw.write("X509 SubjectKeyIdentifier Hex: "+ hexSKI +"\n");

				try {
					sw.write("PEM: " + toPEM("CERTIFICATE", mlSigner.getEncoded()));
				} catch (CertificateEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
			}
		}
		
		sw.append("\n");		
		i = 0;
		
		for (Certificate cert : cscaCerts) {
			X509Certificate x509Cert = (X509Certificate) cert;
			String subjectDN = x509Cert.getSubjectDN().toString();
			String issuerDN = x509Cert.getIssuerDN().toString();
			DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
			SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());

			String b64SKI = Base64.getEncoder().encodeToString(skid.getKeyIdentifier());
			String hexSKI = HexString.bufferToHex(skid.getKeyIdentifier());

			if (filterBySubject == null || b64SKI.equals(filterBySubject) || hexSKI.equals(filterBySubject)) {

				sw.append("+++++++++++++ CSCA Cert no. "+(++i)+" ++++++++++++++\n");	
				sw.write("Subject DN: "+subjectDN+"\n");
				sw.write("Issuer  DN: "+issuerDN+"\n");
				sw.write("X509 SubjectKeyIdentifier B64: "+ b64SKI + "\n");
				sw.write("X509 SubjectKeyIdentifier Hex: "+ hexSKI + "\n");
				try {
					if (showDetails)
						sw.write("PEM: " + toPEM("CERTIFICATE", cert.getEncoded()));
				} catch (CertificateEncodingException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				} catch (IOException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				sw.append("Public Key Algorithm: " + x509Cert.getPublicKey().getAlgorithm() + "\n");
				sw.append("Signing Algorithm: " + x509Cert.getSigAlgName() + "\n");
				if (showDetails) sw.append(x509Cert.toString());
				
	//			try {
	//				cert.verify(x509Cert.getPublicKey());
	//				sw.append("Signature is valid.");
	//
	//			} catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException | NoSuchProviderException | SignatureException e) {
	//				// TODO Auto-generated catch block
	//				sw.append(e.getMessage());
	//			} 
				
				sw.append("\n\n");
			}
		}
		return sw.toString(); //sw.toString();
		
	}

	public String getTrustListJson(boolean showDetails, String filterBySubject) {
		StringWriter swTrust = new StringWriter();
		Set<String> pkis = new HashSet<String>();

		swTrust.append("{\n");
		swTrust.append("  \"ICAO\": {\n");
		
		for (Certificate cert : cscaCerts) {
			X509Certificate x509Cert = (X509Certificate) cert;
			DEROctetString oct = (DEROctetString) DEROctetString.getInstance(x509Cert.getExtensionValue("2.5.29.14"));
			SubjectKeyIdentifier skid = SubjectKeyIdentifier.getInstance(oct.getOctets());

			String b64SKI = Base64.getEncoder().encodeToString(skid.getKeyIdentifier());
			String hexSKI = HexString.bufferToHex(skid.getKeyIdentifier());

			if (filterBySubject == null || b64SKI.equals(filterBySubject) || hexSKI.equals(filterBySubject)) {
				printTrustEntry(swTrust, x509Cert, pkis);
			}
		}

		swTrust.append("  }\n");
		swTrust.append("}");

		return swTrust.toString(); //sw.toString();
	
	}
	
	/* PRIVATE METHODS BELOW */
	

	private CMSSignedData buildCMSSignedDataFromBinary(byte[] binary) {
		CMSSignedData signedData =null;
		try {
			signedData = new CMSSignedData(binary);
		} catch (CMSException e) {
			System.out.println("Could find a SignedData object: "+e.getLocalizedMessage());
		}
		return signedData;
	}
	
	private SignerInformation parseSignerInfo() {
		
		Iterator<SignerInformation> iterator = cmsSignedData.getSignerInfos().getSigners().iterator();

		this.signerInfo = iterator.next(); //TODO This only returns the first Signer. Are there more?
		return signerInfo;
	}
	
	private List<Certificate> parseMasterList() {
		
		if (cscaCerts == null) { cscaCerts = new ArrayList<Certificate>(); }
		
		String id_MasterList = cmsSignedData.getSignedContentTypeOID(); 
		CMSProcessableByteArray content = (CMSProcessableByteArray) cmsSignedData.getSignedContent();
		
		byte[] octets = null;
		if (id_MasterList.equals("2.23.136.1.1.2")) {
			
			ByteArrayOutputStream bout = new ByteArrayOutputStream();
			
			try {
				content.write(bout);
			} catch (IOException | CMSException e) {
				System.out.println("parseMasterList() Exception: "+e.getLocalizedMessage());
			}
			octets = bout.toByteArray();
		}

		try {
			Enumeration<?> derObjects = ASN1Sequence.getInstance(octets).getObjects();
			CertificateFactory cf = CertificateFactory.getInstance("X.509","BC");
			
			while (derObjects.hasMoreElements()) {
				ASN1Integer version = (ASN1Integer)derObjects.nextElement(); //Should be 0
//				if (version!=0) throw Exception; //TODO Exception model
				ASN1Set certSet = ASN1Set.getInstance(derObjects.nextElement());
				
				Enumeration<Certificate> certs = certSet.getObjects();				
				while (certs.hasMoreElements()) {
					org.bouncycastle.asn1.x509.Certificate certAsASN1Object = org.bouncycastle.asn1.x509.Certificate.getInstance(certs.nextElement());
					cscaCerts.add(cf.generateCertificate(new ByteArrayInputStream(certAsASN1Object.getEncoded())));
				}
				
			}

		} catch (Exception e) {
			System.out.println("parseMasterList() Exception: "+e.getLocalizedMessage());
		}

		return cscaCerts;
	}
	
	private List<Certificate> parseMasterListSignerCertificates() {
		
		List<Certificate> result = new ArrayList<Certificate>();

		// The signer certifcate(s)
		Store<X509CertificateHolder> certStore = cmsSignedData.getCertificates();
		
		JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
		converter.setProvider("BC");
		
		ArrayList<X509CertificateHolder> certificateHolders = (ArrayList<X509CertificateHolder>)certStore.getMatches(null); 

		 for(X509CertificateHolder holder: certificateHolders){
			try {
				X509Certificate cert = converter.getCertificate(holder);
				result.add(cert);
			} catch (CertificateException e) {
				System.out.println("parseMasterListSignerCertificates() Exception: "+e.getLocalizedMessage());
			} 
		 }
		return result;
	}
}
