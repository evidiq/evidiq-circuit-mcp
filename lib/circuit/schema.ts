import { CircuitTraceStep } from "./report.js";

export interface SchemaInspectInput {
  payload: any;
  expectedSchema?: Record<string, any>;
  baselineTypes?: Record<string, string>;
}

export function inspectPayloadSchema(input: SchemaInspectInput, currentSequenceOffset: number = 5): CircuitTraceStep[] {
  const steps: CircuitTraceStep[] = [];

  // Step 6: schema.validation_failed
  let schemaPassed = true;
  let schemaActual = "Payload conforms to schema structure";
  let schemaMessage = "JSON response payload matches expected schema structure";

  if (input.expectedSchema && typeof input.expectedSchema === "object") {
    const requiredFields = input.expectedSchema.required || [];
    const missingFields: string[] = [];

    if (typeof input.payload !== "object" || input.payload === null) {
      schemaPassed = false;
      schemaActual = `Payload type is ${typeof input.payload}, expected object`;
      schemaMessage = "Payload is not a valid JSON object";
    } else {
      for (const field of requiredFields) {
        if (!(field in input.payload)) {
          missingFields.push(field);
        }
      }
      if (missingFields.length > 0) {
        schemaPassed = false;
        schemaActual = `Missing required fields: ${missingFields.join(", ")}`;
        schemaMessage = `Payload schema validation failed (missing: ${missingFields.join(", ")})`;
      }
    }
  }

  steps.push({
    sequence: currentSequenceOffset + 1,
    checkId: "schema.validation_failed",
    category: "schema",
    severity: "CRITICAL",
    passed: schemaPassed,
    expected: "payload matches JSON Schema required fields",
    actual: schemaActual,
    message: schemaMessage,
  });

  // Step 7: schema.field_type_drift
  let driftPassed = true;
  let driftActual = "No field type drift detected";
  let driftMessage = "Field types conform to established baseline";

  if (input.baselineTypes && typeof input.payload === "object" && input.payload !== null) {
    const driftedFields: string[] = [];
    for (const [key, expectedType] of Object.entries(input.baselineTypes)) {
      if (key in input.payload) {
        const actualType = typeof input.payload[key];
        if (actualType !== expectedType) {
          driftedFields.push(`${key}: expected ${expectedType}, got ${actualType}`);
        }
      }
    }

    if (driftedFields.length > 0) {
      driftPassed = false;
      driftActual = driftedFields.join("; ");
      driftMessage = `Type drift detected on fields: ${driftedFields.join("; ")}`;
    }
  }

  steps.push({
    sequence: currentSequenceOffset + 2,
    checkId: "schema.field_type_drift",
    category: "schema",
    severity: "MEDIUM",
    passed: driftPassed,
    expected: "field data types match baselineTypes schema",
    actual: driftActual,
    message: driftMessage,
  });

  return steps;
}
