import java.net.URI
import java.util.Properties

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.jetbrains.kotlin.android)
    id("maven-publish")
}

group = "io.klever"
version = System.getenv("LIB_VERSION")?.removePrefix("v") ?: "LOCAL"

android {
    namespace = "uniffi.kos_mobile"
    compileSdk = 34
    defaultConfig {
        minSdk = 27
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
        }
    }
}

dependencies {
    implementation(libs.java.jna)
    testImplementation(libs.junit)
}

publishing {
    repositories {
        maven {
            name = "GithubPackages"
            url = URI.create("https://maven.pkg.github.com/daniellfalcao/kos-rs-fork")
            credentials {
                username = ""
                password = (System.getenv("GITHUB_TOKEN")
                    ?: (getLocalProperties()["git.token"] as? String?)
                    ?: "")
            }
        }
    }

    publications {
        create("KOS", MavenPublication::class.java) {
            artifactId = "kos-mobile"
            afterEvaluate {
                artifact(tasks.getByName("bundleReleaseAar"))
            }
        }
    }
}

tasks.register("copyKOSMobileDarwinAarch64LibForTestDebugUnitTest", Copy::class) {
    dependsOn("processDebugUnitTestJavaRes")
    from("$rootDir/lib/src/main/jniLibs/darwin-aarch64") {
        include("libkos_mobile.dylib")
    }
    into("$rootDir/lib/build/tmp/kotlin-classes/debugUnitTest/darwin-aarch64")
}

afterEvaluate {
    tasks.named("testDebugUnitTest") {
        dependsOn("copyKOSMobileDarwinAarch64LibForTestDebugUnitTest")
    }
}

fun getLocalProperties(): Properties = System.getProperties().apply {
    try {
        load(File("${rootDir}${File.separator}local.properties").inputStream())
    } catch (_: Exception) {
    }
}