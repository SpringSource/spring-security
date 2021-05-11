/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package s101;

import java.io.File;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.provider.Property;
import org.gradle.api.tasks.JavaExec;

public class S101Plugin implements Plugin<Project> {
	@Override
	public void apply(Project project) {
		project.getExtensions().add("s101", new S101PluginExtension(project));
		project.getTasks().register("s101Install", S101Install.class, this::configure);
		project.getTasks().register("s101Configure", S101Configure.class, this::configure);
		project.getTasks().register("s101", JavaExec.class, this::configure);
	}

	private void configure(S101Install install) {
		install.setDescription("Installs Structure101 to your filesystem");
	}

	private void configure(S101Configure configure) {
		configure.setDescription("Applies a default Structure101 configuration to the project");
	}

	private void configure(JavaExec exec) {
		exec.setDescription("Runs Structure101 headless analysis, installing and configuring if necessary");
		Project project = exec.getProject();
		S101PluginExtension extension = project.getExtensions().getByType(S101PluginExtension.class);
		exec
				.workingDir(extension.getInstallationDirectory())
				.classpath(new File(extension.getInstallationDirectory().get(), "structure101-java-build.jar"))
				.args(new File(extension.getConfigurationDirectory().get(), "config.xml"))
				.args("-licensedirectory=" + extension.getLicenseDirectory().get())
				.systemProperty("s101.label", computeLabel(extension).get())
				.doFirst((task) -> installAndConfigureIfNeeded(project));
	}

	private Property<String> computeLabel(S101PluginExtension extension) {
		boolean baselined = extension.getConfigurationDirectory().get().toPath()
				.resolve("repository").resolve("snapshots").resolve("baseline").toFile().exists();
		if (!baselined) {
			return extension.getLabel().convention("baseline");
		}
		return extension.getLabel().convention("recent");
	}

	private void installAndConfigureIfNeeded(Project project) {
		S101Configurer configurer = new S101Configurer(project);
		S101PluginExtension extension = project.getExtensions().getByType(S101PluginExtension.class);
		File installationDirectory = extension.getInstallationDirectory().get();
		if (!installationDirectory.exists()) {
			configurer.install(installationDirectory);
		}
		File configurationDirectory = extension.getConfigurationDirectory().get();
		if (!configurationDirectory.exists()) {
			configurer.configure(installationDirectory, configurationDirectory);
		}
	}
}
