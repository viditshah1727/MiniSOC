-- CreateEnum
CREATE TYPE "Role" AS ENUM ('ADMIN', 'ANALYST', 'VIEWER');

-- CreateEnum
CREATE TYPE "Severity" AS ENUM ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL');

-- CreateEnum
CREATE TYPE "EventType" AS ENUM ('AUTH_SUCCESS', 'AUTH_FAILURE', 'NETWORK_CONNECTION', 'PROCESS_EXECUTION', 'DNS_QUERY', 'FILE_DOWNLOAD');

-- CreateEnum
CREATE TYPE "AlertStatus" AS ENUM ('OPEN', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE');

-- CreateEnum
CREATE TYPE "IncidentStatus" AS ENUM ('OPEN', 'INVESTIGATING', 'RESOLVED', 'CLOSED');

-- CreateEnum
CREATE TYPE "IndicatorType" AS ENUM ('IP', 'DOMAIN', 'HASH');

-- CreateEnum
CREATE TYPE "Reputation" AS ENUM ('MALICIOUS', 'SUSPICIOUS', 'BENIGN');

-- CreateEnum
CREATE TYPE "ActivityType" AS ENUM ('CREATED', 'STATUS_CHANGE', 'ASSIGNMENT', 'NOTE', 'ALERT_LINKED');

-- CreateTable
CREATE TABLE "users" (
    "id" SERIAL NOT NULL,
    "email" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "password_hash" TEXT NOT NULL,
    "role" "Role" NOT NULL DEFAULT 'VIEWER',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "users_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "events" (
    "id" SERIAL NOT NULL,
    "timestamp" TIMESTAMPTZ(3) NOT NULL,
    "source" TEXT NOT NULL,
    "event_type" "EventType" NOT NULL,
    "severity" "Severity" NOT NULL DEFAULT 'INFO',
    "source_ip" INET,
    "destination_ip" INET,
    "destination_port" INTEGER,
    "hostname" TEXT,
    "username" TEXT,
    "message" TEXT NOT NULL,
    "metadata" JSONB,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "detection_rules" (
    "id" SERIAL NOT NULL,
    "code" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "threshold" INTEGER,
    "window_minutes" INTEGER,
    "enabled" BOOLEAN NOT NULL DEFAULT true,
    "recommended_steps" TEXT[],
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "detection_rules_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "mitre_techniques" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "tactics" TEXT[],
    "description" TEXT NOT NULL,

    CONSTRAINT "mitre_techniques_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "threat_intelligence" (
    "id" SERIAL NOT NULL,
    "indicator" TEXT NOT NULL,
    "type" "IndicatorType" NOT NULL,
    "reputation" "Reputation" NOT NULL,
    "confidence" INTEGER NOT NULL,
    "source" TEXT NOT NULL,
    "description" TEXT,
    "first_seen" TIMESTAMPTZ(3) NOT NULL,
    "last_seen" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "threat_intelligence_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "alerts" (
    "id" SERIAL NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "severity" "Severity" NOT NULL,
    "status" "AlertStatus" NOT NULL DEFAULT 'OPEN',
    "risk_score" INTEGER NOT NULL,
    "risk_factors" JSONB NOT NULL,
    "evidence" JSONB NOT NULL,
    "dedup_key" TEXT NOT NULL,
    "source_ip" INET,
    "hostname" TEXT,
    "username" TEXT,
    "detected_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,
    "rule_id" INTEGER NOT NULL,
    "event_id" INTEGER NOT NULL,
    "mitre_technique_id" TEXT,
    "threat_intel_id" INTEGER,
    "incident_id" INTEGER,

    CONSTRAINT "alerts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "incidents" (
    "id" SERIAL NOT NULL,
    "title" TEXT NOT NULL,
    "description" TEXT,
    "severity" "Severity" NOT NULL,
    "status" "IncidentStatus" NOT NULL DEFAULT 'OPEN',
    "assignee_id" INTEGER,
    "resolved_at" TIMESTAMPTZ(3),
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "incidents_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "activities" (
    "id" SERIAL NOT NULL,
    "type" "ActivityType" NOT NULL,
    "message" TEXT NOT NULL,
    "alert_id" INTEGER,
    "incident_id" INTEGER,
    "user_id" INTEGER,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "activities_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "_RuleTechniques" (
    "A" INTEGER NOT NULL,
    "B" TEXT NOT NULL,

    CONSTRAINT "_RuleTechniques_AB_pkey" PRIMARY KEY ("A","B")
);

-- CreateTable
CREATE TABLE "_AlertEvidence" (
    "A" INTEGER NOT NULL,
    "B" INTEGER NOT NULL,

    CONSTRAINT "_AlertEvidence_AB_pkey" PRIMARY KEY ("A","B")
);

-- CreateIndex
CREATE UNIQUE INDEX "users_email_key" ON "users"("email");

-- CreateIndex
CREATE INDEX "events_timestamp_idx" ON "events"("timestamp");

-- CreateIndex
CREATE INDEX "events_event_type_timestamp_idx" ON "events"("event_type", "timestamp");

-- CreateIndex
CREATE INDEX "events_source_ip_event_type_timestamp_idx" ON "events"("source_ip", "event_type", "timestamp");

-- CreateIndex
CREATE INDEX "events_username_event_type_timestamp_idx" ON "events"("username", "event_type", "timestamp");

-- CreateIndex
CREATE UNIQUE INDEX "detection_rules_code_key" ON "detection_rules"("code");

-- CreateIndex
CREATE UNIQUE INDEX "threat_intelligence_indicator_type_key" ON "threat_intelligence"("indicator", "type");

-- CreateIndex
CREATE INDEX "alerts_status_severity_idx" ON "alerts"("status", "severity");

-- CreateIndex
CREATE INDEX "alerts_detected_at_idx" ON "alerts"("detected_at");

-- CreateIndex
CREATE INDEX "alerts_source_ip_idx" ON "alerts"("source_ip");

-- CreateIndex
CREATE INDEX "alerts_rule_id_dedup_key_detected_at_idx" ON "alerts"("rule_id", "dedup_key", "detected_at");

-- CreateIndex
CREATE INDEX "alerts_incident_id_idx" ON "alerts"("incident_id");

-- CreateIndex
CREATE INDEX "incidents_status_idx" ON "incidents"("status");

-- CreateIndex
CREATE INDEX "activities_alert_id_created_at_idx" ON "activities"("alert_id", "created_at");

-- CreateIndex
CREATE INDEX "activities_incident_id_created_at_idx" ON "activities"("incident_id", "created_at");

-- CreateIndex
CREATE INDEX "_RuleTechniques_B_index" ON "_RuleTechniques"("B");

-- CreateIndex
CREATE INDEX "_AlertEvidence_B_index" ON "_AlertEvidence"("B");

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_rule_id_fkey" FOREIGN KEY ("rule_id") REFERENCES "detection_rules"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_event_id_fkey" FOREIGN KEY ("event_id") REFERENCES "events"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_mitre_technique_id_fkey" FOREIGN KEY ("mitre_technique_id") REFERENCES "mitre_techniques"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_threat_intel_id_fkey" FOREIGN KEY ("threat_intel_id") REFERENCES "threat_intelligence"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "incidents" ADD CONSTRAINT "incidents_assignee_id_fkey" FOREIGN KEY ("assignee_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "activities" ADD CONSTRAINT "activities_alert_id_fkey" FOREIGN KEY ("alert_id") REFERENCES "alerts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "activities" ADD CONSTRAINT "activities_incident_id_fkey" FOREIGN KEY ("incident_id") REFERENCES "incidents"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "activities" ADD CONSTRAINT "activities_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_RuleTechniques" ADD CONSTRAINT "_RuleTechniques_A_fkey" FOREIGN KEY ("A") REFERENCES "detection_rules"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_RuleTechniques" ADD CONSTRAINT "_RuleTechniques_B_fkey" FOREIGN KEY ("B") REFERENCES "mitre_techniques"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_AlertEvidence" ADD CONSTRAINT "_AlertEvidence_A_fkey" FOREIGN KEY ("A") REFERENCES "alerts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "_AlertEvidence" ADD CONSTRAINT "_AlertEvidence_B_fkey" FOREIGN KEY ("B") REFERENCES "events"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- CheckConstraints (hand-written: Prisma's schema language cannot express CHECKs).
-- The database itself rejects impossible values, even if application validation is bypassed.
ALTER TABLE "events" ADD CONSTRAINT "events_destination_port_check" CHECK ("destination_port" BETWEEN 0 AND 65535);
ALTER TABLE "threat_intelligence" ADD CONSTRAINT "threat_intelligence_confidence_check" CHECK ("confidence" BETWEEN 0 AND 100);
ALTER TABLE "threat_intelligence" ADD CONSTRAINT "threat_intelligence_seen_order_check" CHECK ("first_seen" <= "last_seen");
ALTER TABLE "alerts" ADD CONSTRAINT "alerts_risk_score_check" CHECK ("risk_score" BETWEEN 0 AND 100);
ALTER TABLE "activities" ADD CONSTRAINT "activities_target_check" CHECK ("alert_id" IS NOT NULL OR "incident_id" IS NOT NULL);
