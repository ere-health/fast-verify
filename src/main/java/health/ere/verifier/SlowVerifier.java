package health.ere.verifier;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Holder;

import de.gematik.ws.conn.connectorcommon.v5.Status;
import de.gematik.ws.conn.connectorcontext.v2.ContextType;
import de.gematik.ws.conn.signatureservice.v7.VerificationResultType;
import de.gematik.ws.conn.signatureservice.v7.VerifyDocument.OptionalInputs;
import de.gematik.ws.conn.signatureservice.v7.VerifyDocumentResponse.OptionalOutputs;
import de.gematik.ws.conn.signatureservice.wsdl.v7.FaultMessage;
import de.gematik.ws.conn.signatureservice.wsdl.v7.SignatureServicePortTypeV740;
import de.gematik.ws.conn.signatureservice.wsdl.v7.SignatureServiceV740;
import oasis.names.tc.dss._1_0.core.schema.Base64Signature;
import oasis.names.tc.dss._1_0.core.schema.SignatureObject;
import oasis.names.tc.dss._1_0.core.schema.UseVerificationTimeType;
import oasis.names.tc.dss_x._1_0.profiles.verificationreport.schema_.ReturnVerificationReport;

public class SlowVerifier {
    public static boolean verify(InputStream is) {
        try {
            ContextType contextType = new ContextType();
            contextType.setMandantId("Incentergy");
            contextType.setWorkplaceId("1786_A1");
            contextType.setClientSystemId("Incentergy");

            SignatureServicePortTypeV740 service = new SignatureServiceV740(SlowVerifier.class
                    .getResource("/SignatureService.wsdl")).getSignatureServicePortV740();

            BindingProvider bindingProvider = (BindingProvider) service;
            bindingProvider.getRequestContext().put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY,
                    "https://10.0.0.98:443/ws/SignatureService");

            String connectorTlsCertAuthStorePwd = "N4rouwibGRhne2Fa";
            FileInputStream certificateInputStream = new FileInputStream("/home/manuel/Desktop/RU-Connector-Cert/no_ec_incentergy.p12");

            SSLContext sslContext = SSLContext.getInstance("TLS");

            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(certificateInputStream, connectorTlsCertAuthStorePwd.toCharArray());

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(ks, connectorTlsCertAuthStorePwd.toCharArray());

            sslContext.init(kmf.getKeyManagers(), new TrustManager[]{new SSLUtilities.FakeX509TrustManager()},
                    null);

            bindingProvider.getRequestContext().put("com.sun.xml.ws.transport.https.client.SSLSocketFactory",
                sslContext.getSocketFactory());
            bindingProvider.getRequestContext().put("com.sun.xml.ws.transport.https.client.hostname.verifier",
                    new SSLUtilities.FakeHostnameVerifier());

            OptionalInputs arg2 = new OptionalInputs();
            UseVerificationTimeType uvtt = new UseVerificationTimeType();
            uvtt.setCurrentTime(true);
            arg2.setUseVerificationTime(uvtt);
            ReturnVerificationReport rvr = new ReturnVerificationReport();
            rvr.setIncludeVerifier(true);
            rvr.setIncludeCertificateValues(true);
            rvr.setIncludeRevocationValues(true);
            rvr.setExpandBinaryValues(true);
            arg2.setReturnVerificationReport(rvr);

            SignatureObject arg4 = new SignatureObject();
            Base64Signature base64Signature = new Base64Signature();
            base64Signature.setType("urn:ietf:rfc:5652");
            base64Signature.setValue(is.readAllBytes());
            arg4.setBase64Signature(base64Signature);
            
            boolean arg5 = true;
            Holder<Status> arg6 = new Holder<>();
            Holder<VerificationResultType> arg7 = new Holder<>();
            Holder<OptionalOutputs> arg8 = new Holder<>();
            
            service.verifyDocument(contextType, "NONE", arg2, null, arg4, arg5, arg6, arg7, arg8);

            if(arg7.value.getHighLevelResult().equals("VALID")) {
                return true;
            } else {
                throw new RuntimeException("Signature status is: "+arg7.value.getHighLevelResult());
            }
        } catch(NoSuchAlgorithmException| KeyStoreException| UnrecoverableKeyException| KeyManagementException| IOException| FaultMessage| CertificateException e) {
            throw new RuntimeException(e);
        }

    }
}
