package com.umantis.seniordev.filerepo;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.annotation.Resource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;
import com.umantis.seniordev.util.TestConstants;
import com.umantis.seniordev.util.TestContext;
import com.umantis.seniordev.util.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = { TestContext.class })
@WebAppConfiguration
public class FileRepositoryDownloadTest {

    @Resource
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private String jwtTokenCersei;
    private String jwtTokenSansa;
    private TestUtils testUtils;

    @Before
    public void setUp() throws Exception {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
        this.testUtils = new TestUtils(this.mockMvc);
        this.jwtTokenCersei = this.testUtils.obtainJwtToken(TestConstants.USERNAME_CERSEI, TestConstants.PASS_CERSEI);
        this.jwtTokenSansa = this.testUtils.obtainJwtToken(TestConstants.USERNAME_SANSA, TestConstants.PASS_SANSA);
    }

    @Test
    public void shouldGet404() throws Exception {
        // given
        String jwtToken = this.jwtTokenCersei;
        String nonExistingId = "nonExistingId";

        // when & then
        this.mockMvc.perform(get(TestConstants.DOWNLOAD_ENDPOINT)
                                     .param(TestConstants.DOWNLOAD_FILE_ID_PARAM_NAME, nonExistingId)
                                     .header(TestConstants.AUTH_TOKEN_KEY, jwtToken))
                .andExpect(status().is(HttpStatus.NOT_FOUND.value()));
    }

    @Test
    public void shouldNotHaveAccessToFile() throws Exception {
        // given
        MvcResult mvcResult = this.testUtils.performUpload(TestUtils.loadFile(TestConstants.UMANTIS_LOGO_PNG), this.jwtTokenSansa)
                .andExpect(status().is(HttpStatus.OK.value()))
                .andReturn();
        String fileId = mvcResult.getResponse().getContentAsString();

        // when & then
        this.mockMvc.perform(get(TestConstants.DOWNLOAD_ENDPOINT)
                                     .param(TestConstants.DOWNLOAD_FILE_ID_PARAM_NAME, fileId)
                                     .header(TestConstants.AUTH_TOKEN_KEY, this.jwtTokenCersei))
                .andExpect(status().is(HttpStatus.FORBIDDEN.value()));
    }

    @Test
    public void shouldGetOwnFile() throws Exception {
        // given
        MockMultipartFile myFile = TestUtils.loadFile(TestConstants.UMANTIS_LOGO_PNG);
        MvcResult mvcResult = this.testUtils.performUpload(myFile, this.jwtTokenCersei)
                .andExpect(status().is(HttpStatus.OK.value()))
                .andReturn();
        String fileId = mvcResult.getResponse().getContentAsString();

        // when & then
        this.mockMvc.perform(get(TestConstants.DOWNLOAD_ENDPOINT)
                                     .param(TestConstants.DOWNLOAD_FILE_ID_PARAM_NAME, fileId)
                                     .header(TestConstants.AUTH_TOKEN_KEY, this.jwtTokenCersei))
                .andExpect(status().is(HttpStatus.OK.value()))
                .andExpect(content().contentType(MediaType.IMAGE_PNG))
                .andExpect(content().bytes(myFile.getBytes()));
    }
}
