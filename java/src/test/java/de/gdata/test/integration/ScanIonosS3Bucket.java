package de.gdata.test.integration;

import com.amazonaws.auth.AWSCredentialsProvider;
import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.client.builder.AwsClientBuilder;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ListObjectsV2Request;
import com.amazonaws.services.s3.model.ListObjectsV2Result;
import com.amazonaws.services.s3.model.S3Object;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import de.gdata.vaas.Vaas;
import de.gdata.vaas.VaasConfig;
import de.gdata.vaas.authentication.ClientCredentialsGrantAuthenticator;
import de.gdata.vaas.messages.VaasVerdict;
import de.gdata.vaas.options.ForFileOptions;
import io.github.cdimascio.dotenv.Dotenv;

import java.io.File;
import java.io.FileOutputStream;
import java.net.URI;
import java.nio.file.Files;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ScanIonosS3Bucket {
    public static void main(String[] args) throws Exception {
        // Load environment variables
        Dotenv dotenv = Dotenv.load();
        String CLIENT_ID = dotenv.get("CLIENT_ID");
        String CLIENT_SECRET = dotenv.get("CLIENT_SECRET");
        String VAAS_URL = dotenv.get("VAAS_URL");
        String TOKEN_URL = dotenv.get("TOKEN_URL");
        String S3_ACCESS_KEY = dotenv.get("S3_ACCESS_KEY");
        String S3_SECRET_KEY = dotenv.get("S3_SECRET_KEY");
        String S3_URL = dotenv.get("S3_URL");
        String S3_BUCKET = dotenv.get("S3_BUCKET");
        String S3_REGION = dotenv.get("S3_REGION");

        // Build VaaS
        ClientCredentialsGrantAuthenticator authenticator = new ClientCredentialsGrantAuthenticator(CLIENT_ID, CLIENT_SECRET, new URI(TOKEN_URL));
        VaasConfig vaasConfig = new VaasConfig(Duration.ofMinutes(30).getSeconds() * 1000, false, true, new URI(VAAS_URL));
        Vaas vaas = new Vaas(vaasConfig, authenticator);

        // List S3 bucket
        AWSCredentialsProvider awsCredentialsProvider = new AWSCredentialsProvider() {
            @Override
            public BasicAWSCredentials getCredentials() {
                return new BasicAWSCredentials(S3_ACCESS_KEY, S3_SECRET_KEY);
            }

            @Override
            public void refresh() {
            }
        };
        AwsClientBuilder.EndpointConfiguration s3EndpointConfig = new AwsClientBuilder.EndpointConfiguration(S3_URL, S3_REGION);
        AmazonS3 s3Client = AmazonS3ClientBuilder
                .standard()
                .withEndpointConfiguration(s3EndpointConfig)
                .withCredentials(awsCredentialsProvider)
                .build();
        ListObjectsV2Request req = new ListObjectsV2Request().withBucketName(S3_BUCKET);
        ListObjectsV2Result result;
        List<String> keys = new ArrayList<>();
        result = s3Client.listObjectsV2(req);
        for (S3ObjectSummary objectSummary : result.getObjectSummaries()) {
            keys.add(objectSummary.getKey());
        }

        // Iterate over everything in S3 bucket and scan with VaaS
        List<Map<String, Object>> results = new ArrayList<>();
        for (String key : keys) {
            try {
                System.out.println("Current key: " + key + " (" + keys.indexOf(key) + "/" + keys.size() + ")");

                // Download file from S3 to temp file
                S3Object s3Object = s3Client.getObject(S3_BUCKET, key);
                long fileSize = s3Object.getObjectMetadata().getContentLength();
                if (fileSize > 2500000000L) {
                    System.out.println("File too big, skipping: " + key);
                    continue;
                }
                File tempFile = File.createTempFile("vaas-sample-", null);
                try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                    s3Object.getObjectContent().transferTo(fos);
                }

                // Scan file with VaaS and track time
                long startTime = System.currentTimeMillis();
                ForFileOptions forFileOptions = new ForFileOptions(false, true, "LD-big-big-files-01");
                VaasVerdict vaasVerdict = vaas.forFileAsync(tempFile.toPath(), forFileOptions).get();
                long endTime = System.currentTimeMillis();
                double executionTime = (endTime - startTime);

                // Save VaaS verdict and execution time
                Map<String, Object> resultData = new HashMap<>();
                resultData.put("key", key);
                resultData.put("executionTimeInMs", String.format("%.3f", executionTime));
                Map<String, Object> verdictData = new HashMap<>();
                verdictData.put("sha256", vaasVerdict.getSha256());
                verdictData.put("verdict", vaasVerdict.getVerdict());
                verdictData.put("detection", vaasVerdict.getDetection());
                verdictData.put("fileType", vaasVerdict.getFileType());
                verdictData.put("mimeType", vaasVerdict.getMimeType());
                resultData.put("verdict", verdictData);
                results.add(resultData);

                // Delete temp file
                Files.delete(tempFile.toPath());
            } catch (Exception e) {
                System.out.println("Error processing key: " + key);
                e.printStackTrace();
            }
        }

        // Write results to file
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
        objectMapper.writeValue(new File("results-" + S3_BUCKET + ".json"), results);

        System.out.println("Results written to results-" + S3_BUCKET + ".json");
    }
}