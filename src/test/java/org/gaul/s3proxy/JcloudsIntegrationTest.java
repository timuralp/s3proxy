/*
 * Copyright 2014-2015 Andrew Gaul <andrew@gaul.org>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.gaul.s3proxy;

import java.io.IOException;
import java.util.Properties;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Throwables;
import com.google.common.util.concurrent.Uninterruptibles;

import org.jclouds.Constants;
import org.jclouds.blobstore.BlobStoreContext;
import org.jclouds.s3.blobstore.integration.S3BlobIntegrationLiveTest;

import org.junit.AfterClass;

import org.testng.SkipException;

public final class JcloudsIntegrationTest extends S3BlobIntegrationLiveTest {
    protected static final int AWAIT_CONSISTENCY_TIMEOUT_SECONDS =
            Integer.parseInt(
                    System.getProperty(
                            "test.blobstore.await-consistency-timeout-seconds",
                            "0"));
    private S3Proxy s3Proxy;
    private BlobStoreContext context;

    @Override
    public void testPutObjectStream()
            throws InterruptedException, IOException, ExecutionException {
        throw new SkipException("not passing yet");
    }

    @Override
    public void testSetBlobAccess() throws Exception {
        throw new SkipException("not passing yet");
    }

    @AfterClass
    public void tearDown() throws Exception {
        s3Proxy.stop();
        context.close();
    }

    @Override
    protected void awaitConsistency() {
        Uninterruptibles.sleepUninterruptibly(
                AWAIT_CONSISTENCY_TIMEOUT_SECONDS, TimeUnit.SECONDS);
    }

    @Override
    protected Properties setupProperties() {
        TestUtils.S3ProxyLaunchInfo info;
        try {
            info = TestUtils.startS3Proxy();
            s3Proxy = info.getS3Proxy();
            context = info.getBlobStore().getContext();
        } catch (Exception e) {
            throw Throwables.propagate(e);
        }
        Properties props = super.setupProperties();
        props.setProperty(Constants.PROPERTY_IDENTITY, info.getS3Identity());
        props.setProperty(Constants.PROPERTY_CREDENTIAL,
                info.getS3Credential());
        props.setProperty(Constants.PROPERTY_ENDPOINT,
                info.getEndpoint().toString());
        props.setProperty(Constants.PROPERTY_STRIP_EXPECT_HEADER, "true");
        return props;
    }
}
