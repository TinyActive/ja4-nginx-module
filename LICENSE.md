# JA4 Nginx Module - Proprietary License

**Version 2.1 - Effective Date: June 2026**

## 1. License Grant

TinyActive ("Licensor") grants you ("Licensee"), including individuals, companies, and other legal entities, a non-exclusive, non-transferable, non-sublicensable license to use this JA4 Nginx Module ("Software") in accordance with this License Agreement.

This License distinguishes between **Free Use** (Section 2) and **Commercial Use** (Section 3). Use that falls under Commercial Use requires a separate paid Commercial License Agreement.

## 2. Free Use (No Fee Required)

You may use the Software **without charge** for each **Deployment** (defined below) that does **not** generate **Revenue**. Free Use applies **per system, website, API, or service endpoint**, not only to an organization as a whole.

### 2.1 Permitted Free Use

- **Internal organizational use** by companies, agencies, and institutions for security monitoring, threat detection, logging, research, evaluation, or operational protection of internal systems
- **Infrastructure and systems that do not generate Revenue**, such as internal portals, intranets, development/staging environments, and non-customer-facing backends
- **Customer-facing websites and applications that do not generate Revenue**, including but not limited to:
  - Corporate introduction and company profile websites
  - Informational, institutional, or marketing websites that do not sell products or services online
  - Blogs, news pages, documentation sites, and community pages **without monetization** (no paid subscriptions, no advertising revenue, no paid content, no lead-generation fees tied to the site itself)
  - Public landing pages whose sole purpose is brand presence or communication, not revenue generation
- **Personal and non-profit use** for learning, experimentation, or community projects without monetization
- **Educational use** in academic or training settings
- Any other non-revenue-generating purpose explicitly approved in writing by TinyActive

### 2.2 Definitions

**"Deployment"** means a distinct nginx instance, virtual host, domain, subdomain, API gateway, or logically separated service where the Software is installed and used to process traffic for a specific website, application, or API.

If a Deployment primarily supports or enables access to a Revenue-generating service, that Deployment shall itself be deemed Revenue-generating for licensing purposes.

**"Revenue"** means any monetary income or commercial consideration generated directly or indirectly through, facilitated by, promoted by, or commercially supported by a Deployment, in **any form**, including but not limited to: product or service sales, subscriptions, transaction or processing fees, licensing fees, advertising revenue, affiliate commissions, donations accepted as part of a commercial operation, paid memberships, marketplace fees, and any other direct or indirect commercial gain attributable to that Deployment.
Systems that process, support, secure, analyze, or facilitate traffic for a Revenue-generating Deployment shall be considered part of that Deployment

**"Direct Revenue from the Software"** means Revenue generated specifically by selling, licensing, or offering the Software or functionality substantially equivalent to or derived from the Software (for example, paid JA4 fingerprinting SaaS or TLS analytics APIs).

Revenue-generating Deployments include not only the customer-facing website, application, API, or service through which Revenue is generated, but also any Deployment that primarily processes, routes, secures, monitors, analyzes, proxies, filters, load-balances, caches, or otherwise supports traffic for such Revenue-generating website, application, API, or service.

For licensing purposes, a Deployment that primarily supports a Revenue-generating Deployment shall itself be deemed a Revenue-generating Deployment, regardless of whether customers interact with it directly or whether Revenue is collected through that specific Deployment.


### 2.3 Per-Deployment Licensing

License classification is determined **separately for each Deployment**. The same Licensee may operate both Free Use and Commercial Use Deployments at the same time, provided that:

- Each Free Use Deployment does not generate Revenue
- Each Revenue-generating Deployment holds a valid Commercial License
- Free Use and Commercial Use traffic are not commingled on the same Deployment in a way that obscures Revenue-generating use

**Example — payment gateway provider:**
- **Free Use:** The public corporate homepage (company introduction, product overview, contact page) that generates no Revenue
- **Commercial Use (paid license required):** Payment processing APIs, merchant dashboards, checkout endpoints, or any Deployment through which transaction fees, merchant subscriptions, or other payment-related Revenue is generated

**Examples of Free Use:**
- A company deploys the Software on an internal nginx gateway for SOC TLS fingerprinting
- A corporate website at `www.example.com` with company profile, blog posts, and news — no online sales or monetization
- A university lab or staging environment with no Revenue

**Examples requiring a Commercial License:**
- An e-commerce store, SaaS product, paid API, online marketplace, or subscription service — **any Deployment that generates Revenue in any form**
- Reselling or bundling the Software as part of a commercial security product
- Generating Direct Revenue from the Software itself

### 2.4 When Classification Is Unclear

Evaluate each Deployment based on whether **that specific Deployment** generates Revenue. If a customer-facing site later introduces monetization (ads, paid plans, online sales, paid APIs, etc.), it becomes Commercial Use from that point forward.

When in doubt whether a specific Deployment is Free Use or Commercial Use, contact TinyActive before deployment.

## 3. Commercial Use (Paid License Required)

### 3.1 When a Commercial License Is Required

You **must** obtain a separate **Commercial License Agreement** and pay applicable fees for **each Deployment** that:

- Generates **Revenue** in any form, as defined in Section 2.2 — including e-commerce, paid APIs, SaaS, subscriptions, transaction-based services, advertising-supported sites, and any other Revenue-generating website, application, or API
- Generates **Direct Revenue from the Software**, as defined in Section 2.2
- Offers the Software, or services powered by it, to third parties for a fee or as part of a paid offering
- Integrates the Software into commercial products, platforms, or managed services sold or licensed to customers
- Otherwise uses the Software in any context where fees apply under a Commercial License Agreement with TinyActive

**Important:** A customer-facing website does **not** automatically require a Commercial License. Only Deployments that **generate Revenue** require payment. Non-revenue customer-facing sites such as corporate introduction pages and non-monetized blogs remain Free Use under Section 2.1.

Continued use of any Revenue-generating Deployment without a valid Commercial License constitutes a material breach of this License.

### 3.2 Obtaining a Commercial License

To obtain a Commercial License, you must:

- Contact TinyActive for pricing and terms
- Execute a separate Commercial License Agreement
- Pay all applicable license fees as specified in that agreement
- Comply with all terms of the Commercial License Agreement

## 4. General Restrictions (All Use)

Regardless of Free Use or Commercial Use, you are **prohibited** from:

- Modifying, adapting, or creating derivative works from the Software without written permission from TinyActive, except as expressly permitted in a Commercial License Agreement
- Reverse engineering, decompiling, or attempting to discover non-public aspects of the Software beyond what is permitted by applicable law
- Removing, obscuring, or altering any copyright notices or licensing information
- Sublicensing, renting, leasing, or transferring the Software except as expressly authorized in writing by TinyActive

## 5. Distribution and Sharing

You may share the unmodified Software with others provided that:

- You provide the recipient with a complete copy of this License
- The recipient agrees to all terms and conditions of this License
- No unauthorized modifications have been made to the Software
- It is clear to the recipient whether their intended use is Free Use or requires a Commercial License

## 6. Disclaimer of Warranties

**THE SOFTWARE IS PROVIDED "AS-IS" WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO:**

- Warranties of merchantability or fitness for a particular purpose
- Warranty of non-infringement of third-party rights
- Any other warranties or conditions

Licensor shall not be liable for any damages, including but not limited to:

- Direct, indirect, incidental, special, or consequential damages
- Loss of data, profits, or business interruption
- Any other loss arising from the use or inability to use the Software

## 7. Limitation of Liability

**IN NO EVENT SHALL TINYACTIVE BE LIABLE FOR ANY DAMAGES WHATSOEVER**, whether in an action of contract, negligence, tort, or any other action, even if advised of the possibility of such damages.

## 8. Intellectual Property Rights

All right, title, and interest in and to the Software, including all intellectual property rights, remain the exclusive property of TinyActive. This License does not grant you any ownership rights in the Software.

## 9. Termination

This License is effective until terminated. Your rights under this License will terminate automatically if you fail to comply with any terms or conditions of this License. Upon termination:

- You must cease all use of the Software
- You must destroy all copies of the Software in your possession
- All rights granted herein shall immediately cease

Licensor may terminate this License at any time for any reason with written notice.

## 10. Enforcement and Remedies

- Violation of any provision in this License constitutes a material breach
- Use of the Software in a Commercial Use context without a valid Commercial License may result in retroactive fee assessment, injunctive relief, and other remedies available under law
- TinyActive reserves the right to seek injunctive relief for breaches of this License
- You shall be liable for all damages, attorney fees, and costs incurred by TinyActive in enforcing this License

## 11. Governing Law

This License is governed by and construed in accordance with the laws of Vietnam, without regard to its conflict of law provisions.

## 12. Entire Agreement

This License constitutes the entire agreement between you and TinyActive regarding Free Use of the Software and supersedes all prior negotiations, understandings, and agreements relating to non-commercial licensing. Commercial Use is governed by the separate Commercial License Agreement.


## 13. Acknowledgment

**BY USING THIS SOFTWARE, YOU ACKNOWLEDGE THAT YOU HAVE READ THIS LICENSE, UNDERSTAND ITS TERMS, AND AGREE TO BE BOUND BY ALL OF ITS PROVISIONS. IF ANY DEPLOYMENT GENERATES REVENUE IN ANY FORM OR OTHERWISE REQUIRES A COMMERCIAL LICENSE UNDER SECTION 3, YOU AGREE TO OBTAIN AND PAY FOR A COMMERCIAL LICENSE FOR THAT DEPLOYMENT BEFORE OR CONTINUING SUCH USE.**

---

For commercial licensing inquiries, pricing, or permission requests, please contact:

**TinyActive** via Telegram: http://t.me/vouuvhb
