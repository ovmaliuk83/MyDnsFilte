// gradle/init.gradle.kts

// Адрес зеркала Maven Central от Google
val mirrorUrl = "https://maven-central.storage-download.googleapis.com/maven2/"

// Функция для замены официального Maven Central на зеркало
fun RepositoryHandler.useMirror() {
    val centralRepos = filterIsInstance<MavenArtifactRepository>().filter {
        it.url.host == "repo.maven.apache.org" || it.url.host == "repo1.maven.org"
    }
    if (centralRepos.isNotEmpty()) {
        removeAll(centralRepos.toSet()) // Удаляем официальный Central
    }
    // Добавляем зеркало, если его ещё нет
    if (none { it is MavenArtifactRepository && it.url.toString() == mirrorUrl }) {
        maven(mirrorUrl) {
            name = "GoogleMavenCentralMirror"
        }
    }
}

// Применяем замену ко всем репозиториям во всех проектах
settingsEvaluated {
    pluginManagement.repositories.useMirror()
    dependencyResolutionManagement.repositories.useMirror()
}

allprojects {
    buildscript.repositories.useMirror()
    afterEvaluate {
        repositories.useMirror()
    }
}
