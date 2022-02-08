package health.ere.verifier;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.Store;

import de.gematik.pki.certificate.CertificateProfile;
import de.gematik.pki.certificate.TucPki018Verifier;
import de.gematik.pki.exception.GemPkiException;
import de.gematik.pki.ocsp.OcspRespCache;
import de.gematik.pki.tsl.TslConverter;
import de.gematik.pki.tsl.TslInformationProvider;
import de.gematik.pki.tsl.TspService;

public class FastVerifier {

    private static final CertificateProfile certificateProfile = CertificateProfile.C_HP_AUT_RSA;
    private static final List<CertificateProfile> certificateProfiles = List.of(certificateProfile);
    private static final OcspRespCache ocspRespCache = new OcspRespCache(30);
    private final static String PRODUCT_TYPE_IDP = "IDP";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static boolean verify(InputStream is) {
        return verify(is, false);
    }

    public static boolean verify(InputStream is, boolean verifyCertificate) {
        try {
            CMSSignedData signedData = new CMSSignedData(is);

            Store<X509CertificateHolder> certStore = signedData.getCertificates();
            SignerInformationStore  signers = signedData.getSignerInfos();
            Collection<SignerInformation> c = signers.getSigners();
            for(SignerInformation signer : signers.getSigners()) {
                Selector<X509CertificateHolder> sid = signer.getSID();
                for(X509CertificateHolder cert : certStore.getMatches(sid)) {
                    if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                        if(verifyCertificate) {
                            verifyCertificate(cert );
                        }
                        return true;
                    } 
                }
            }
            return false;
        } catch(CMSException | OperatorCreationException | CertificateException | IllegalStateException | GemPkiException | IOException ex) {
            throw new RuntimeException(ex);
        }
    }

    public static void verifyCertificate(X509CertificateHolder certificateHolder) throws CertificateException, GemPkiException, MalformedURLException, IOException {
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate( certificateHolder );
        

        // CN=GEM.HBA-qCA24 TEST-ONLY, O=gematik GmbH NOT-VALID, C=DE
        // String url = "https://download-ref.tsl.ti-dienste.de/ECC/ECC-RSA_TSL-ref.xml";
        String url = "https://download-ref.tsl.ti-dienste.de/TSL-ref.xml";

        final List<TspService> tspServiceList = new TslInformationProvider(
            TslConverter.bytesToTsl(new URL(url).openStream().readAllBytes()).orElseThrow())
            .getTspServices();
        
        TucPki018Verifier tucPki018Verifier = TucPki018Verifier.builder()
        .productType(PRODUCT_TYPE_IDP)
        .tspServiceList(tspServiceList)
        .certificateProfiles(certificateProfiles)
        .ocspRespCache(ocspRespCache)
        .build();
        tucPki018Verifier.performTucPki18Checks(cert);
    }
/*

    void verifyCertificate(X509CertificateHolder cert) {
        

        // Code based on: https://github.com/apache/nifi/blob/master/nifi-nar-bundles/nifi-framework-bundle/nifi-framework/nifi-web/nifi-web-security/src/main/java/org/apache/nifi/web/security/x509/ocsp/OcspCertificateValidator.java#L278
        InputStream ocspResponseStream;
        BasicOCSPResp basicOcspResponse;
        try {
            String ocspUrl = getOcspUrl(cert);
            ocspResponseStream = new URL(ocspUrl).openStream();
            OCSPResp oCSPResp = new OCSPResp(ocspResponseStream);
            basicOcspResponse = (BasicOCSPResp) oCSPResp.getResponseObject();
        } catch (IOException | OCSPException e2) {
            throw new IllegalArgumentException("Could not parse OCSP response", e2);
        }

        BigInteger subjectSerialNumber = cert.getSerialNumber();
        // validate the response
        final SingleResp[] responses = basicOcspResponse.getResponses();
        for (SingleResp singleResponse : responses) {
            final CertificateID responseCertificateId = singleResponse.getCertID();
            final BigInteger responseSerialNumber = responseCertificateId.getSerialNumber();

            if (responseSerialNumber.equals(subjectSerialNumber)) {
                Object certStatus = singleResponse.getCertStatus();

                // interpret the certificate status
                if (certStatus instanceof RevokedStatus) {
                    throw new IllegalStateException("certificate status is revoked");
                }
            }
        }
    }

    public String getOcspUrl(X509CertificateHolder cert) throws IOException {
        ASN1OctetString octetString = cert.getExtension(Extension.authorityInfoAccess).getExtnValue();
        ASN1Primitive obj = JcaX509ExtensionUtils.parseExtensionValue(octetString.getEncoded());
        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(obj);

        AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        for (AccessDescription accessDescription : accessDescriptions) {
            boolean correctAccessMethod = accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.ocspAccessMethod);
            if (!correctAccessMethod) {
                continue;
            }

            GeneralName name = accessDescription.getAccessLocation();
            if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                continue;
            }

            DERIA5String derStr = DERIA5String.getInstance((ASN1TaggedObject) name.toASN1Primitive(), false);
            return derStr.getString();
        }

        return null;
    }
*/

}
