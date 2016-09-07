package io.hawt.git;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import static io.hawt.git.GitFacadeIT.assertConfigDirectoryExists;
import static io.hawt.git.GitFacadeIT.assertFileContents;
import static io.hawt.git.GitFacadeIT.createTestGitFacade;

/**
 * Tests we can clone a remote repo
 */
public class GitCloneIT {
    GitFacade git = createTestGitFacade();

    @Before
    public void init() throws Exception {
        git.init();
    }

    @After
    public void destroy() throws Exception {
        git.destroy();
    }

    @Test
    public void clonedRemoteRepo() throws Exception {
        assertConfigDirectoryExists(git);

        String contents = assertFileContents(git, "master", "/ReadMe.md");
        System.out.println("Read me is: " + contents.trim());
    }
}
