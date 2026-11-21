import SwiftUI

struct AccountView: View {
    @EnvironmentObject private var vm: SideBridgeViewModel
    @State private var appleId = ""
    @State private var password = ""
    @State private var twoFactorCode = ""

    var body: some View {
        NavigationStack {
            List {
                if let session = vm.appleSession {
                    Section("Apple Developer Session") {
                        LabeledContent("Apple ID", value: session.appleId)
                        LabeledContent("Team", value: "\(session.teamName) (\(session.teamId))")
                        LabeledContent("Account Tier", value: session.isFreePersonalTeam ? "Free Personal Team (7-Day)" : "Paid Developer")

                        Button("Refresh Certificates & Quota") {
                            Task { await vm.refreshAccountQuota() }
                        }
                        Button("Sign Out", role: .destructive) {
                            vm.signOutAppleID()
                        }
                    }

                    Section("Active Development Certificate") {
                        if let cert = vm.activeCertRecord {
                            LabeledContent("Name", value: cert.displayName)
                            LabeledContent("Serial", value: cert.serialNumber)
                            LabeledContent("SHA-1", value: String(cert.sha1Thumbprint.prefix(16)) + "...")
                        } else {
                            Text("No active certificate cached. SideBridge will verify listAllDevelopmentCerts and issue a CSR on next install.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        }
                    }

                    Section("App ID Quota (\(vm.registeredAppIds.count) / 10 Weekly Slots)") {
                        if vm.registeredAppIds.isEmpty {
                            Text("No App IDs registered on this team yet.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                        } else {
                            ForEach(vm.registeredAppIds) { appId in
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(appId.name).font(.subheadline)
                                    Text(appId.identifier)
                                        .font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                    }
                } else {
                    Section("Sign In with Apple ID (GrandSlam SRP-6a)") {
                        TextField("Apple ID Email", text: $appleId)
                            .textInputAutocapitalization(.never)
                            .keyboardType(.emailAddress)
                            .autocorrectionDisabled()
                        SecureField("Password", text: $password)

                        Button(vm.isAuthenticating ? "Authenticating..." : "Sign In") {
                            Task { await vm.signInAppleID(email: appleId, password: password) }
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(appleId.isEmpty || password.isEmpty || vm.isAuthenticating)
                    }

                    if vm.pendingTwoFactor != nil {
                        Section("Two-Factor Authentication") {
                            TextField("6-Digit Code", text: $twoFactorCode)
                                .keyboardType(.numberPad)
                            Button("Verify 2FA Code") {
                                Task { await vm.submitTwoFactor(code: twoFactorCode) }
                            }
                            .buttonStyle(.borderedProminent)
                            .disabled(twoFactorCode.count < 6 || vm.isAuthenticating)
                        }
                    }
                }

                if let err = vm.authErrorMessage {
                    Section("Error") {
                        Text(err).font(.footnote).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Account")
        }
    }
}
