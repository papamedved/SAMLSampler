/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package ru.pflb.samlsampler;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.io.StringWriter;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.apache.jmeter.config.Arguments;
import org.apache.jmeter.functions.Variable;
import org.apache.jmeter.protocol.java.sampler.AbstractJavaSamplerClient;
import org.apache.jmeter.protocol.java.sampler.JavaSamplerContext;
import org.apache.jmeter.samplers.SampleResult;
import org.apache.jmeter.threads.JMeterContextService;
import org.apache.jmeter.threads.JMeterVariables;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 *
 * @author user
 */
public class SamlSampler extends AbstractJavaSamplerClient implements Serializable{
    private static final long serialVersionUID = 1L;
    
    @Override
    public Arguments getDefaultParameters() {
        Arguments defaultParameters = new Arguments();
        defaultParameters.addArgument("Path to EMP private key", "c:\\Projects\\SAMLR\\pflb_saml_key.pem");
        defaultParameters.addArgument("AssertionConsumerServiceURL", "http://pflbmail.hopto.org/acs_post");
        defaultParameters.addArgument("Destination", "https://esia-portal1.test.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO");
        defaultParameters.addArgument("Assertion", "http://pflbmail.hopto.org");
        defaultParameters.addArgument("URL_SSO", "https://esia-portal1.test.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO?SAMLRequest=");
        defaultParameters.addArgument("SigAlg", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        defaultParameters.addArgument("SaveToVarSAMLRequest", "varSAMLRequest");
        defaultParameters.addArgument("SaveToVarRelayState", "varRelayState");
        defaultParameters.addArgument("SaveToVarSignature", "varSignature");
        //defaultParameters.addArgument("SEARCHFOR", "newspaint");
        return defaultParameters;
    }
    
    @Override
    public SampleResult runTest(JavaSamplerContext jsc) {
        String pathToPrivateKey                 = jsc.getParameter( "Path to EMP private key" );
        String strAssertionConsumerServiceURL   = jsc.getParameter("AssertionConsumerServiceURL");
        String strDestination                   = jsc.getParameter("Destination");
        String strAssertion                     = jsc.getParameter("Assertion");
        String strURL_SSO                       = jsc.getParameter("URL_SSO");
        String strSigAlg                        = jsc.getParameter("SigAlg");
        
        String varSAMLRequest                  = jsc.getParameter("SaveToVarSAMLRequest");
        String varRelayState                   = jsc.getParameter("SaveToVarRelayState");
        String varSignature                    = jsc.getParameter("SaveToVarSignature");
        
        SampleResult result = new SampleResult();
        result.sampleStart(); // start stopwatch
        
        
        try {
 
            result.sampleEnd();
            
            String xml = createSamlXml(strAssertionConsumerServiceURL, strDestination, strAssertion);
            
            //PrivateKey privateKey = getEPMPrivateKey(pathToPrivateKey);
            PrivateKey privateKey = getEPMPrivateKey(pathToPrivateKey);

            String encoded = deflateAndBase64encode(xml);
                encoded.replaceAll("\n|\r\n", "");
            String sSAMLRequestNOTencoded = encoded;
            encoded = URLEncoder.encode(encoded, "UTF-8");
            
            //strURL_SSO += encoded;
            
            //String URL = URLEncoder.encode(encoded, "UTF-8");
            //byte[] signature = getSignature(URL, privateKey, "SHA1withRSA");
            
            //String sSAMLRequest = new String(outbase64);
            String sSAMLRequest = encoded;
            String sRelayState = UUID.randomUUID().toString();
            String sSigAlg = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
            //
            
            strURL_SSO = strURL_SSO+sSAMLRequest+"&RelayState=_"+URLEncoder.encode(sRelayState, "UTF-8")+"&SigAlg="+URLEncoder.encode(strSigAlg, "UTF-8");
            //strURL_SSO = URLEncoder.encode(strURL_SSO+sSAMLRequest+"&RelayState=_"+sRelayState+"&SigAlg="+strSigAlg,"UTF-8");
            byte[] signature = getSignature(strURL_SSO, privateKey, "SHA1withRSA");
            String sSignature = new String(Base64.encode(signature));

            
            JMeterVariables vars = JMeterContextService.getContext().getVariables();
            vars.putObject(varSAMLRequest, sSAMLRequestNOTencoded);
            vars.putObject(varRelayState, "_"+sRelayState);
            vars.putObject("varSigAlg", strSigAlg);
            vars.putObject(varSignature, sSignature);
            JMeterContextService.getContext().setVariables( vars );
            result.setResponseData(
                "===================================================================================================" + "\r\n" +
                "URL: " + strURL_SSO + "\r\n" +
                "===================================================================================================" + "\r\n" +
                "XML: " + xml + "\r\n" +
                "===================================================================================================" + "\r\n" +
                "SAMLRequest: " + sSAMLRequest + "\r\n" +
                "===================================================================================================" + "\r\n" +
                "RelayState: " + "_" + sRelayState + "\r\n" +
                "===================================================================================================" + "\r\n" +
                "SigAlg: " + sSigAlg + "\r\n" +
                "===================================================================================================" + "\r\n" +
                "Signature: " + sSignature
            , "UTF-8");
            //result.setResponseData("OK", "UTF-8");
            result.setSuccessful( true );
            result.setResponseMessage( "Successfully performed action" );
            result.setResponseCodeOK(); // 200 code
        } catch (Exception e) {
            java.io.StringWriter stringWriter = new java.io.StringWriter();
            e.printStackTrace( new java.io.PrintWriter( stringWriter ) );
            result.setResponseData( stringWriter.toString(), "UTF-8" );
            result.setDataType( org.apache.jmeter.samplers.SampleResult.TEXT );
            result.setResponseCode( "500" );
        }
        return result;
    }
    
    private static String deflateAndBase64encode(String xml) throws IOException{
        Deflater deflater = new Deflater(Deflater.DEFLATED, true);
        
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);        

        deflaterOutputStream.write(xml.getBytes());
        deflaterOutputStream.close();

        //String encoded = new BASE64Encoder().encode(byteArrayOutputStream.toByteArray());
        String encoded = new String(Base64.encode(byteArrayOutputStream.toByteArray()));
        return encoded;
    }
    
    /**
     * 
     * @param strAssertionConsumerServiceURL = "http://pflbmail.hopto.org/acs_post"
     * @param strDestination = "https://esia-portal1.test.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO"
     * @param strAssertion = "http://pflbmail.hopto.org"
     * @return
     * @throws TransformerException 
     */
    private static String createSamlXml(String strAssertionConsumerServiceURL, String strDestination, String strAssertion) throws TransformerException, ParserConfigurationException{
        String xml = "";
        DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
        DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
        Document doc = docBuilder.newDocument();
        Element rootElement = doc.createElement("saml2p:AuthnRequest");
        doc.appendChild(rootElement);
        Attr attr = doc.createAttribute("xmlns:saml2p");
        attr.setValue("urn:oasis:names:tc:SAML:2.0:protocol");
        rootElement.setAttributeNode(attr);
            Attr attr1 = doc.createAttribute("AssertionConsumerServiceURL");
            attr1.setValue("http://pflbmail.hopto.org/acs_post");
            rootElement.setAttributeNode(attr1);
                Attr attr3 = doc.createAttribute("Destination");
                attr3.setValue("https://esia-portal1.test.gosuslugi.ru/idp/profile/SAML2/Redirect/SSO");
                rootElement.setAttributeNode(attr3);
                    Attr attr4 = doc.createAttribute("ForceAuthn");
                    attr4.setValue("false");
                    rootElement.setAttributeNode(attr4);
                        Attr attr5 = doc.createAttribute("ID");
                        attr5.setValue("_"+UUID.randomUUID().toString());
                        rootElement.setAttributeNode(attr5);
                            Attr attr6 = doc.createAttribute("IsPassive");
                            attr6.setValue("false");
                            rootElement.setAttributeNode(attr6);
                                Attr attr7 = doc.createAttribute("IssueInstant");
                                    SimpleDateFormat simpleDateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
                                    simpleDateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
                                    attr7.setValue(simpleDateFormat.format(new Date().getTime())+"Z");
                                rootElement.setAttributeNode(attr7);
                                    Attr attr8 = doc.createAttribute("ProtocolBinding");
                                    attr8.setValue("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
                                    rootElement.setAttributeNode(attr8);
                                        Attr attr9 = doc.createAttribute("Version");
                                        attr9.setValue("2.0");
                                        rootElement.setAttributeNode(attr9);
        Element staff = doc.createElement("saml2:Issuer");
        rootElement.appendChild(staff);
            Attr attr10 = doc.createAttribute("xmlns:saml2");
            attr10.setValue("urn:oasis:names:tc:SAML:2.0:assertion");
            staff.setAttributeNode(attr10);

            staff.appendChild(doc.createTextNode("http://pflbmail.hopto.org"));
            rootElement.appendChild(staff);


        // write the content into xml file
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        Transformer transformer = transformerFactory.newTransformer();
        DOMSource source = new DOMSource(doc);

        StringWriter writer = new StringWriter();
        StreamResult resultXML = new StreamResult(writer);

        transformer.transform(source, resultXML);
        xml = writer.getBuffer().toString().replaceAll("\n|\r", "");
        
        return xml;
    }
    
    /**
     * 
     * @param signData 
     * @param pk
     * @param algorithm - set "SHA1withRSA"
     * @return 
     */
    
    private static byte[] getSignature(String signData, PrivateKey pk, String algorithm){
      try {
        Signature signature = Signature.getInstance(algorithm);
        signature.initSign(pk);
        signature.update(signData.getBytes());
        byte[] signedData = signature.sign();
        
        return signedData;
        
      } catch(Exception e){
        java.io.StringWriter stringWriter = new java.io.StringWriter();
        e.printStackTrace( new java.io.PrintWriter( stringWriter ) ); 
        
        return null;
      }
    }
    
    private static PrivateKey getEPMPrivateKey(String pathToPemPrivateKey) {
        PEMParser pEMParser;      
        try {
            pEMParser = new PEMParser(new InputStreamReader(new FileInputStream(pathToPemPrivateKey)));
            Object privateKeyObject = pEMParser.readObject();
            byte[] keyBytes = PrivateKeyInfo.getInstance(privateKeyObject).getEncoded();
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");        
            PrivateKey pk = kf.generatePrivate(spec);
            
            return pk;
        } catch (Exception ePEM) {
            java.io.StringWriter stringWriter = new java.io.StringWriter();
            ePEM.printStackTrace( new java.io.PrintWriter( stringWriter ) );
            PrivateKey pk = null;
            return pk;
        }
    }
    
    private static String bytes2String(byte[] bytes) {
        StringBuilder string = new StringBuilder();
        for (byte b : bytes) {
            String hexString = Integer.toHexString(0x00FF & b);
            string.append(hexString.length() == 1 ? "0" + hexString : hexString);
        }
        return string.toString();
    }
    
}
