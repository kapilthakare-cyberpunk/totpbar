// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "totpbar",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "totpbar", targets: ["totpbar"])
    ],
    targets: [
        .executableTarget(
            name: "totpbar",
            path: ".",
            sources: ["TOTPBar.swift"]
        )
    ]
)
