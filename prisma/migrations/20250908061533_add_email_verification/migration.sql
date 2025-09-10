-- AlterTable
ALTER TABLE "public"."User" ADD COLUMN     "isVerified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "verifyToken" TEXT;
