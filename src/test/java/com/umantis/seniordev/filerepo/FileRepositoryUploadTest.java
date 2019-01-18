package com.umantis.seniordev.filerepo;

import static org.junit.Assert.assertFalse;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.annotation.Resource;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.StringUtils;
import org.springframework.web.context.WebApplicationContext;
import com.umantis.seniordev.util.TestConstants;
import com.umantis.seniordev.util.TestContext;
import com.umantis.seniordev.util.TestUtils;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = {TestContext.class})
@WebAppConfiguration
public class FileRepositoryUploadTest {

    @Resource
    private WebApplicationContext webApplicationContext;

    private String jwtTokenCersei;
    private String jwtTokenWalda;
    private TestUtils testUtils;

    @Before
    public void setUp() throws Exception {
        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(this.webApplicationContext).build();
        this.testUtils = new TestUtils(mockMvc);

        this.jwtTokenCersei = this.testUtils.obtainJwtToken(TestConstants.USERNAME_CERSEI, TestConstants.PASS_CERSEI);
        this.jwtTokenWalda = this.testUtils.obtainJwtToken(TestConstants.USERNAME_WALDA, TestConstants.PASS_WALDA);
    }

    @Test
    public void shouldNotAuthenticate() throws Exception {
        // given
        String garbageJwtToken = "garbage"; // with this token authentication will fail
        MockMultipartFile myFile = TestUtils.loadFile(TestConstants.UMANTIS_LOGO_PNG);

        // when & then
        this.testUtils.performUpload(myFile, garbageJwtToken)
                .andExpect(status().is(HttpStatus.UNAUTHORIZED.value()));

    }

    @Test
    public void shouldNotAuthorize() throws Exception {
        // given
        MockMultipartFile myFile = TestUtils.loadFile(TestConstants.UMANTIS_LOGO_PNG);

        // when & then
        this.testUtils.performUpload(myFile, this.jwtTokenWalda)
                .andExpect(status().is(HttpStatus.FORBIDDEN.value()));
    }

    @Test
    public void shouldSuccessfulyUpload() throws Exception {
        // given
        MockMultipartFile myFile = TestUtils.loadFile(TestConstants.UMANTIS_LOGO_PNG);

        // when & then
        String id = this.testUtils.performUpload(myFile, this.jwtTokenCersei)
                .andExpect(status().is(HttpStatus.OK.value()))
                .andReturn().getResponse().getContentAsString();
        assertFalse(StringUtils.isEmpty(id));
    }
}
