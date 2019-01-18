package com.umantis.seniordev.util;

import static org.junit.Assert.assertFalse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.fileUpload;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

public class TestUtils {

    private MockMvc mockMvc;

    public TestUtils(final MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    public String obtainJwtToken(final String username, final String password) throws Exception {
        MockHttpServletResponse response = this.mockMvc
                .perform(createAuthGet(username, password))
                .andExpect(status().isOk()).andExpect(content().contentType(TestConstants.APPLICATION_JSON_UTF8))
                .andReturn().getResponse();
        return TestUtils.getAuthToken(response);
    }

    public static MockHttpServletRequestBuilder createAuthGet(final String username, final String password) {
        return get(TestConstants.AUTH_ENDPOINT)
                .param(TestConstants.AUTH_USERNAME_PARAM_NAME, username)
                .param(TestConstants.AUTH_PASS_PARAM_NAME, password);
    }

	public static MockMultipartFile loadFile(final String fileName) throws IOException {
        return new MockMultipartFile(TestConstants.UPLOAD_FILE_PARAM_NAME, ClassLoader.getSystemResourceAsStream(fileName));
    }

    public ResultActions performUpload(final MockMultipartFile myFile, final String jwtToken) throws Exception {
        return this.mockMvc.perform(fileUpload(TestConstants.UPLOAD_ENDPOINT)
                                            .file(myFile)
                                            .header(TestConstants.AUTH_TOKEN_KEY, jwtToken));
    }

	public static String getAuthToken(MockHttpServletResponse response) throws UnsupportedEncodingException {
		String token = response.getContentAsString();
		assertFalse(StringUtils.isEmpty(token));
		return token;
	}
}
