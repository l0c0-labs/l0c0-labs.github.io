---
title: "Shadow IT, API Authorization, and AI-Assisted Attacks"
description: "A closer look at exposed support services, the ARTEX planning loop, and why login security alone does not prevent data exposure."
date: 2026-10-14
slug: "shadow-it-api-authorization"
categories: [incident-analysis]
language: en
author: "Inwoo Na"
draft: false
---

While reading the SK shieldus guide on recent financial-sector incidents, I paid more attention to the affected services than to the AI tool.

The guide describes loan-agent lookup pages, employee support systems, and externally managed web services. These are not the main banking application, but some of them still provide access to customer or employee information.

That is enough to make them useful targets.

This post is based on the guide's October 6, 2026 information cutoff. Some incident details were still under investigation. I have not reproduced the attacks or independently examined the affected systems.

## A lookup function can be the entry point

We often picture a data breach as an attacker gaining a shell, moving through the network, and downloading a database.

A lookup API can expose data without that sequence.

Consider the following illustrative request. It is not an endpoint from the reported incidents.

```http
GET /api/applications/1042
Authorization: Bearer <user-token>
```

The server recognizes the token and returns application 1042.

Now suppose the same user requests application 1043, which belongs to another customer. If the server checks only whether the token is valid, it may return that record too.

The request is valid HTTP. The application may return a normal 200 response. There does not have to be a malicious file or an unusual payload.

The missing check is whether this user may access this particular application.

This is an object-level authorization problem, often discussed as BOLA or IDOR. The guide also describes services with missing authentication. Those are separate failures: one allows access without establishing identity; the other allows an identified user to access data outside their permissions.

The distinction matters when choosing a fix.

## MFA does not check which record you may read

MFA helps protect the login process. It does not, by itself, decide which customer records a logged-in user may retrieve.

For a loan-agent service, the question might be whether the application is assigned to that agent. For a partner portal, it might be whether the requested record belongs to that partner's organization.

The server has to enforce that relationship.

A simplified authorization decision could look like this:

```text
1. Validate the session or access token.
2. Identify the requested record.
3. Check whether the user may access that record.
4. Return only the fields needed for the permitted task.
```

These checks belong on the server. Hiding a menu item or removing a button does not stop a direct API request.

Changing sequential IDs to random identifiers can make guessing harder, but it does not establish permission either. If someone obtains another valid identifier, the same authorization check is still needed.

## Why the surrounding systems matter

In this guide, Shadow IT includes systems and APIs outside the security team's inventory or effective controls.

That is broader than an employee installing an unapproved application.

A service can be part of an ordinary business process and still be poorly accounted for. Someone may know who uses it without knowing who maintains it, which APIs it exposes, or whether its logs reach the monitoring team.

A temporary partner service can also remain online after the original project ends.

The useful questions are quite concrete:

- Is the service reachable from the internet?
- Who owns the application and its security fixes?
- What information can it retrieve?
- Does it enforce the caller's permissions?
- Can the team reconstruct which records were accessed?

Calling a system “internal support” does not answer any of these questions if it is externally reachable.

The guide's point about surrounding systems is worth keeping in mind. A strong primary application does not protect customer information exposed through a separate lookup service.

## What ARTEX adds

The guide describes ARTEX as an AI-assisted penetration-testing platform with a Planner, multiple Workers, and shared stores for assets and exploration results.

The interesting part is the feedback between them.

The Planner creates tasks based on the current state. Workers execute those tasks and record results. Those changes can trigger another planning round. A newly discovered endpoint or finding can therefore influence what happens next.

The source analysis in the guide refers to ARTEX v0.3.14 and describes an event-driven loop. It is more than a fixed script sending the same request repeatedly.

That structure can reduce the manual work needed to explore services and follow up on findings. It does not mean the tool always succeeds, or that adding targets has no cost. Requests, model calls, failed attempts, and verification still take resources.

There is also a limit to what the report tells us. A description of a tool's capabilities is not a complete record of what an attacker did. The guide reconstructs parts of the attack flow from public information and tool behavior, and labels credential stuffing as an inference.

I would keep those distinctions when discussing the incidents. The authorization failures are important without assuming that every stage was fully autonomous.

## What an IP block leaves unresolved

Blocking a known attack IP can interrupt an ongoing attempt. It is useful as an immediate action.

It does not repair the lookup endpoint.

If the caller changes addresses and the endpoint still returns unauthorized records, the same data access remains possible. A request limit applied only per IP can have a similar limitation when requests are distributed across several addresses.

For a lookup service, monitoring should also consider the account, session, endpoint, and requested objects.

One account reading an unusually large number of distinct customer records is worth investigating even if each individual request looks ordinary. Attempts to access records outside the account's assigned scope are another useful signal.

Thresholds need to reflect how the service is used. A batch-processing account and an individual sales agent should not necessarily have the same request limit.

This is also why a WAF cannot replace application authorization. A request for another customer's record may contain no obvious attack string. The application knows which customer belongs to which agent; a generic perimeter rule usually does not.

## Where I would start the review

I would first compare externally visible services with the internal inventory. Any mismatch needs an owner and a decision about whether the service should remain exposed.

For each service that returns sensitive information, I would then review authentication and authorization separately. Testing with two accounts that have different permissions is useful here: can one retrieve a record intended for the other?

The response deserves attention too. An authorized lookup does not necessarily need to return every field stored in the database.

Finally, I would check the audit trail. It should be possible to identify the caller, the requested object, the authorization result, and the time of access without copying unnecessary personal information into the logs.

During an incident, temporary restrictions may be necessary while those defects are corrected. The team also needs someone who can authorize that restriction, including outside normal working hours. A detection rule is of limited use if nobody can act on it.

What I take from this guide is that the API can do exactly what it was programmed to do and still expose information. The missing part may be a permission check, an owner, or a usable audit trail.

AI-assisted tooling makes those gaps easier to explore at scale. The review still starts with the service: who can reach it, what they can request, and what the server actually checks.

## Source

SK shieldus (SK쉴더스), *AI 자동화 공격 시대, Shadow IT를 노린 침해사고 분석 및 대응 가이드*. Subtitle: *ARTEX 기반 금융권 연쇄 침해사고 분석과 API 보안 3단계 대응 방안*. Customer-distribution guide, based on publicly available information as of October 6, 2026.
